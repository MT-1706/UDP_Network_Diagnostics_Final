#!/usr/bin/env python3
"""
End-to-end test WITHOUT Mininet: three fake OpenFlow 1.3 switches connect to a real
`ryu-manager` running dynamic_path_app.py.  The harness relays LLDP between the
switches (so Ryu discovers the links itself), sends ARP like hosts would, captures
the flow-mods Ryu sends, then exercises pinning and a link failure.

    python3 tests/e2e_fake_switches.py  <path-to-ryu-manager>

(use the ryu-manager from your .venv-ryu).  Exit code 0 = all checks passed.
"""
import json, os, socket, struct, subprocess, sys, tempfile, threading, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "..", "dynamic_path_app.py")
RYU = sys.argv[1] if len(sys.argv) > 1 else "ryu-manager"
TMP = tempfile.mkdtemp()
STATE, POLICY = os.path.join(TMP, "state.json"), os.path.join(TMP, "policy.json")
OFPP_CONTROLLER = 0xfffffffd

# (dpid, port) <-> (dpid, port).  s1:1=h1 2=s2 3=s3   s2:1=h3 2=s1 3=s3   s3:1=h2 2=s2 3=s1
WIRES = {(1, 2): (2, 2), (2, 3): (3, 2), (1, 3): (3, 3)}
WIRES.update({v: k for k, v in list(WIRES.items())})
H1, H2, H3 = "00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03"
mac_b = lambda m: bytes(int(x, 16) for x in m.split(":"))

links_up = {(1, 2): True, (2, 3): True, (1, 3): True}
lock = threading.Lock()
flows = {}          # (dpid, eth_dst) -> out port        (priority-5 host flows only)
flood_out = []      # (dpid, [ports]) for non-LLDP packet-outs
switches = {}


def link_key(a, b):
    return tuple(sorted((a, b)))


def link_alive(dpid, port):
    peer = WIRES.get((dpid, port))
    return peer is not None and links_up[link_key(dpid, peer[0])]


def eth_frame(dst, src, ethertype, payload):
    return mac_b(dst) + mac_b(src) + struct.pack("!H", ethertype) + payload


def arp_frame(op, smac, sip, dmac, dip):
    ip = lambda s: bytes(int(x) for x in s.split("."))
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac_b(smac) + ip(sip) + mac_b(dmac) + ip(dip)
    return eth_frame("ff:ff:ff:ff:ff:ff" if op == 1 else dmac, smac, 0x0806, body)


def ipv4_frame(smac, sip, dmac, dip):
    ip = lambda s: bytes(int(x) for x in s.split("."))
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 28, 0, 0, 64, 17, 0) + ip(sip) + ip(dip)
    return eth_frame(dmac, smac, 0x0800, hdr + b"\x00" * 8)


class FakeSwitch(threading.Thread):
    def __init__(self, dpid):
        super().__init__(daemon=True)
        self.dpid, self.sock, self.buf = dpid, None, b""
        self.wlock = threading.Lock()

    def send(self, mtype, body=b"", xid=0):
        with self.wlock:
            self.sock.sendall(struct.pack("!BBHI", 4, mtype, 8 + len(body), xid) + body)

    def port_desc(self, no, down=False):
        return struct.pack("!I4x6s2x16sIIIIIIII", no, mac_b("0a:00:00:00:%02x:%02x" % (self.dpid, no)),
                           b"s%d-eth%d" % (self.dpid, no), 0, 1 if down else 0, 0, 0, 0, 0, 0, 0)

    def packet_in(self, in_port, data):
        match = struct.pack("!HHHBBI", 1, 12, 0x8000, 0, 4, in_port) + b"\x00" * 4
        self.send(10, struct.pack("!IHBBQ", 0xffffffff, len(data), 0, 0, 0) + match + b"\x00\x00" + data)

    def port_status(self, no, down):
        self.send(12, struct.pack("!B7x", 2) + self.port_desc(no, down))

    def run(self):
        self.sock = socket.create_connection(("127.0.0.1", 6653))
        self.send(0)                                           # HELLO
        while True:
            chunk = self.sock.recv(65535)
            if not chunk:
                return
            self.buf += chunk
            while len(self.buf) >= 8:
                _v, t, ln, xid = struct.unpack("!BBHI", self.buf[:8])
                if len(self.buf) < ln:
                    break
                body, self.buf = self.buf[8:ln], self.buf[ln:]
                self.handle(t, xid, body)

    def handle(self, t, xid, body):
        if t == 5:                                             # FEATURES_REQUEST
            self.send(6, struct.pack("!QIBB2xII", self.dpid, 0, 1, 0, 0, 0), xid)
        elif t == 2:                                           # ECHO_REQUEST
            self.send(3, body, xid)
        elif t == 20:                                          # BARRIER_REQUEST
            self.send(21, b"", xid)
        elif t == 18:                                          # MULTIPART_REQUEST
            mp_type = struct.unpack("!H", body[:2])[0]
            if mp_type == 13:                                  # PORT_DESC
                self.send(19, struct.pack("!HH4x", 13, 0) + b"".join(self.port_desc(p) for p in (1, 2, 3)), xid)
        elif t == 13:                                          # PACKET_OUT
            _bid, _inp, alen = struct.unpack("!IIH", body[:10])
            acts, data = body[16:16 + alen], body[16 + alen:]
            ports = [struct.unpack("!I", acts[i + 4:i + 8])[0] for i in range(0, len(acts), 16)]
            ethertype = struct.unpack("!H", data[12:14])[0] if len(data) >= 14 else 0
            if ethertype == 0x88cc:                            # LLDP: relay across live links
                for p in ports:
                    if link_alive(self.dpid, p):
                        peer = WIRES[(self.dpid, p)]
                        switches[peer[0]].packet_in(peer[1], data)
            else:
                with lock:
                    flood_out.append((self.dpid, ports, data))
        elif t == 14:                                          # FLOW_MOD
            self.flow_mod(body)

    def flow_mod(self, b):
        cmd, prio = b[17], struct.unpack("!H", b[22:24])[0]
        mlen = struct.unpack("!H", b[42:44])[0]
        oxm, off = b[44:40 + mlen], 40 + ((mlen + 7) // 8) * 8
        eth_dst, i = None, 0
        while i < len(oxm):
            cls, fld, ln = struct.unpack("!HBB", oxm[i:i + 4])
            if cls == 0x8000 and fld >> 1 == 3:
                eth_dst = ":".join("%02x" % x for x in oxm[i + 4:i + 4 + 6])
            i += 4 + ln
        if prio != 5 or eth_dst is None:
            return
        with lock:
            if cmd == 0 or cmd == 1:                           # ADD / MODIFY
                ins = b[off:]
                port = struct.unpack("!I", ins[8 + 4:8 + 8])[0]   # first output action
                flows[(self.dpid, eth_dst)] = port
            elif cmd in (3, 4):                                # DELETE / DELETE_STRICT
                flows.pop((self.dpid, eth_dst), None)


def rest(path):
    return json.load(urllib.request.urlopen("http://127.0.0.1:8080/v1.0/topology/" + path, timeout=2))


def wait(cond, what, timeout=25):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if cond():
                return time.time() - t0
        except Exception:
            pass
        time.sleep(0.1)
    raise AssertionError("timeout waiting for: " + what)


def state():
    with open(STATE) as f:
        return json.load(f)


def main():
    env = dict(os.environ, SDN_STATE_FILE=STATE, SDN_POLICY_FILE=POLICY)
    log = open(os.path.join(TMP, "ryu.log"), "w")
    ryu = subprocess.Popen([RYU, "--ofp-tcp-listen-port", "6653", "--observe-links",
                            "ryu.topology.switches", APP, "ryu.app.rest_topology"],
                           env=env, stdout=log, stderr=subprocess.STDOUT)
    ok = True
    try:
        wait(lambda: socket.create_connection(("127.0.0.1", 6653), 1), "ryu listening", 15)
        for d in (1, 2, 3):
            switches[d] = FakeSwitch(d)
            switches[d].start()
        t = wait(lambda: len(rest("links")) == 6, "LLDP link discovery (6 directed links)")
        print("PASS  Ryu discovered all 3 links through LLDP relay (%.1fs)" % t)

        # --- hosts appear by ARP ------------------------------------------------
        switches[1].packet_in(1, arp_frame(1, H1, "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2"))
        wait(lambda: {(d, tuple(p)) for d, p, _ in flood_out} >= {(2, (1,)), (3, (1,))}, "ARP flooded to edge ports")
        assert not any(d == 1 for d, _, _ in flood_out), "flooded back out of origin switch"
        print("PASS  unknown ARP is flooded only to host-facing ports of the other switches")
        switches[3].packet_in(1, arp_frame(2, H2, "10.0.0.2", H1, "10.0.0.1"))
        switches[2].packet_in(1, arp_frame(1, H3, "10.0.0.3", "00:00:00:00:00:00", "10.0.0.1"))
        wait(lambda: len(state()["hosts"]) == 3, "3 hosts learned")
        wait(lambda: flows.get((1, H2)) == 3 and flows.get((3, H2)) == 1, "flows towards h2 (direct s1-s3)")
        assert state()["paths"]["10.0.0.1->10.0.0.2"] == ["s1", "s3"], state()["paths"]
        print("PASS  hosts learned; flows installed; default path h1->h2 = s1-s3 (fewest hops)")

        # --- pin the 2-hop path (what 'measure every path' does) ------------------
        json.dump({"seq": 1, "pins": [[1, 2, 3], [3, 2, 1]]}, open(POLICY, "w"))
        wait(lambda: state()["policy_seq"] == 1 and state()["paths"]["10.0.0.1->10.0.0.2"] == ["s1", "s2", "s3"],
             "pinned path applied")
        assert state()["paths"]["10.0.0.2->10.0.0.1"] == ["s3", "s2", "s1"]
        assert flows[(1, H2)] == 2 and flows[(2, H2)] == 3
        print("PASS  policy pin s1-s2-s3 programmed in both directions (state file + flow tables agree)")

        # --- link failure: the pinned s2-s3 link dies -> pin void -> reroute ------
        t0 = time.time()
        links_up[(2, 3)] = False
        switches[2].port_status(3, True)
        switches[3].port_status(2, True)
        wait(lambda: state()["paths"]["10.0.0.1->10.0.0.2"] == ["s1", "s3"], "reroute after link failure")
        dt = time.time() - t0
        assert flows[(1, H2)] == 3
        print("PASS  link s2-s3 failed -> controller rerouted h1->h2 via s1-s3 in %.2fs" % dt)
        assert any("LinkDelete" in e["msg"] for e in state()["events"])

        # --- failure of the last path -> hosts disconnected ---------------------
        links_up[(1, 3)] = False
        switches[1].port_status(3, True)
        switches[3].port_status(3, True)
        wait(lambda: state()["paths"]["10.0.0.1->10.0.0.2"] is None, "h2 unreachable")
        wait(lambda: (1, H2) not in flows, "stale flow removed from s1")
        print("PASS  no route left -> path reported as None and stale flow deleted")

        # --- restore ------------------------------------------------------------
        links_up[(2, 3)] = links_up[(1, 3)] = True
        switches[2].port_status(3, False)
        switches[3].port_status(2, False)
        switches[1].port_status(3, False)
        switches[3].port_status(3, False)
        json.dump({"seq": 2, "pins": []}, open(POLICY, "w"))
        os.utime(POLICY, (time.time() + 1, time.time() + 1))
        wait(lambda: state()["paths"]["10.0.0.1->10.0.0.2"] == ["s1", "s3"], "recovery after restore", 40)
        print("PASS  links restored, pins cleared -> default path back (s1-s3)")
    except AssertionError as e:
        ok = False
        print("FAIL ", e)
        print("---- ryu log tail ----")
        log.flush()
        print(open(os.path.join(TMP, "ryu.log")).read()[-2500:])
    finally:
        ryu.terminate()
        ryu.wait(5)
    print("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
