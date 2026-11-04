#!/usr/bin/env python3

"""
End-to-end test WITHOUT Mininet.
Three fake OpenFlow 1.3 switches connect to the real Ryu controller.
Tests LLDP discovery, ARP host learning, flow installation, path pinning and link failures.

Run using:
python3 tests/e2e_fake_switches.py <path-to-ryu-manager>
"""

import json, os, socket, struct, subprocess, sys, tempfile, threading, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))   # Get dir containing this test file

APP = os.path.join(HERE, "..", "dynamic_path_app.py")   # Locate main Ryu controller application

RYU = sys.argv[1] if len(sys.argv) > 1 else "ryu-manager"   # Get Ryu exec.able path from args/use default cmd

TMP = tempfile.mkdtemp()    # Create a temp dir for test files

STATE, POLICY = os.path.join(TMP, "state.json"), os.path.join(TMP, "policy.json")   # Define paths for ctrl.r state & policy JSON files

OFPP_CONTROLLER = 0xfffffffd    # OpenFlow port # representing the controller

# Define connections b/w switch ports
# s1:1=h1, 2=s2, 3=s3 | s2:1=h3, 2=s1, 3=s3 | s3:1=h2, 2=s2, 3=s1
WIRES = {(1, 2): (2, 2), (2, 3): (3, 2), (1, 3): (3, 3)}

WIRES.update({v: k for k, v in list(WIRES.items())})    # OpenFlow port number representing the controller

H1, H2, H3 = "00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03"  # Define MAC addresses of 3 hosts

mac_b = lambda m: bytes(int(x, 16) for x in m.split(":")) # Conv MAC addr str into bytes

links_up = {(1, 2): True, (2, 3): True, (1, 3): True}   # Initially, all three inter-switch links are active

lock = threading.Lock()     # Lock protects shared data from simultaneous thread access

flows = {}      # Store installed flow rules: (switch ID, dest MAC) -> o/p port

flood_out = []      # Store non-LLDP pkt sent out by switches

switches = {}       # Store simulated switches using their DPID as dictionary keys


# Generate consistent key for link regardless of direction
def link_key(a, b):
    return tuple(sorted((a, b)))


# Check whether a switch port is connected to an active link
def link_alive(dpid, port):
    peer = WIRES.get((dpid, port))
    return peer is not None and links_up[link_key(dpid, peer[0])]


# Construct an Ethernet frame using its header and payload
def eth_frame(dst, src, ethertype, payload):
    return mac_b(dst) + mac_b(src) + struct.pack("!H", ethertype) + payload


# Construct an ARP request or reply packet
def arp_frame(op, smac, sip, dmac, dip):
    ip = lambda s: bytes(int(x) for x in s.split("."))      # Conv IPv4 addr into 4 bytes
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac_b(smac) + ip(sip) + mac_b(dmac) + ip(dip)        # Build ARP header & addr fields
    return eth_frame("ff:ff:ff:ff:ff:ff" if op == 1 else dmac, smac, 0x0806, body)      # Wrap ARP data inside an Ethernet frame


# Construct basic IPv4 pkt carrying UDP data
def ipv4_frame(smac, sip, dmac, dip):
    ip = lambda s: bytes(int(x) for x in s.split("."))    # Conv IPv4 addr into bytes
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 28, 0, 0, 64, 17, 0) + ip(sip) + ip(dip)    # Build IPv4 header
    return eth_frame(dmac, smac, 0x0800, hdr + b"\x00" * 8)    # Add 8-byte UDP header placeholder & wrap it in Ethernet


# Simulate an OpenFlow switch using a separate thread
class FakeSwitch(threading.Thread):

    def __init__(self, dpid):
        super().__init__(daemon=True)  # Run as a bg thread
        self.dpid, self.sock, self.buf = dpid, None, b""  # Store switch ID, socket & receive buffer
        self.wlock = threading.Lock()  # Prevent simultaneous socket writes

    # Send OpenFlow msg to ctrl.r
    def send(self, mtype, body=b"", xid=0):
        with self.wlock:
            self.sock.sendall(struct.pack("!BBHI", 4, mtype, 8 + len(body), xid) + body)     # Build OpenFlow header & attach msg body

    # Create an OpenFlow port description
    def port_desc(self, no, down=False):
        return struct.pack("!I4x6s2x16sIIIIIIII", no, mac_b("0a:00:00:00:%02x:%02x" % (self.dpid, no)),
                           b"s%d-eth%d" % (self.dpid, no), 0, 1 if down else 0, 0, 0, 0, 0, 0, 0)

    # Simulate a PACKET_IN msg from switch to ctrl.r
    def packet_in(self, in_port, data):
        match = struct.pack("!HHHBBI", 1, 12, 0x8000, 0, 4, in_port) + b"\x00" * 4
        self.send(10, struct.pack("!IHBBQ", 0xffffffff, len(data), 0, 0, 0) + match + b"\x00\x00" + data)

    # Notify ctrl.r when a switch port changes state
    def port_status(self, no, down):
        self.send(12, struct.pack("!B7x", 2) + self.port_desc(no, down))

    # Establish connection w/ Ryu & process incoming msgs
    def run(self):
        self.sock = socket.create_connection(("127.0.0.1", 6653))  # Connect to Ryu
        self.send(0)  # Send HELLO message

        while True:
            chunk = self.sock.recv(65535)  # Receive ctrl.r messages
            if not chunk:
                return  # Stop if connection closes

            self.buf += chunk  # Store rcv.d bytes

            # Process complete OpenFlow msgs
            while len(self.buf) >= 8:
                _v, t, ln, xid = struct.unpack("!BBHI", self.buf[:8])  # Decode OpenFlow header

                if len(self.buf) < ln:
                    break  # W8 for complete msg

                body, self.buf = self.buf[8:ln], self.buf[ln:]  # Separate msg body & remaining data
                self.handle(t, xid, body)  # Process rcv.d msg

    # Handle diff OpenFlow msgs rcv.d from Ryu
    def handle(self, t, xid, body):

        if t == 5:  # FEATURES_REQUEST
            # Send switch info & datapath ID
            self.send(6, struct.pack("!QIBB2xII", self.dpid, 0, 1, 0, 0, 0), xid)

        elif t == 2:  # ECHO_REQUEST
            self.send(3, body, xid)  # Reply to keep connection alive

        elif t == 20:  # BARRIER_REQUEST
            self.send(21, b"", xid)  # Confirm barrier request

        elif t == 18:  # MULTIPART_REQUEST
            mp_type = struct.unpack("!H", body[:2])[0]  # Identify rqst type

            if mp_type == 13:  # PORT_DESC
                # Send descriptions of all 3 switch ports
                self.send(19, struct.pack("!HH4x", 13, 0) + b"".join(self.port_desc(p) for p in (1, 2, 3)), xid)

        elif t == 13:  # PACKET_OUT
            _bid, _inp, alen = struct.unpack("!IIH", body[:10])     # Extract buffer ID, input port & action length
            acts, data = body[16:16 + alen], body[16 + alen:]     # Separate actions from packet data
            ports = [struct.unpack("!I", acts[i + 4:i + 8])[0] for i in range(0, len(acts), 16)]    # Extract o/p port no.s from actions
            ethertype = struct.unpack("!H", data[12:14])[0] if len(data) >= 14 else 0    # Identify Ethernet pkt type
            # LLDP
            if ethertype == 0x88cc:  # Relay LLDP packets across active links
                for p in ports:
                    if link_alive(self.dpid, p):
                        peer = WIRES[(self.dpid, p)]
                        switches[peer[0]].packet_in(peer[1], data)
            else:   # Record oth outgoing pkts for later testing
                with lock:
                    flood_out.append((self.dpid, ports, data))

        elif t == 14:  # FLOW_MOD
            self.flow_mod(body)  # Capture ctrl.r's flow rule

    # Decode FLOW_MOD msgs & update simulated flow table
    def flow_mod(self, b):
        cmd, prio = b[17], struct.unpack("!H", b[22:24])[0]     # Extract cmd, priority & match-field len
        mlen = struct.unpack("!H", b[42:44])[0]
        
        oxm, off = b[44:40 + mlen], 40 + ((mlen + 7) // 8) * 8      # Extract OXM match fields and calculate instruction offset
        eth_dst, i = None, 0  # Init dest MAC & parsing index

        while i < len(oxm):     # Read each OXM match field
            cls, fld, ln = struct.unpack("!HBB", oxm[i:i + 4])
            if cls == 0x8000 and fld >> 1 == 3:  # Match Ethernet dest MAC
                eth_dst = ":".join("%02x" % x for x in oxm[i + 4:i + 4 + 6])
            i += 4 + ln  # Move to next match field

        if prio != 5 or eth_dst is None:
            return  # Ignore non-host-specific flow rules

        with lock:
            if cmd == 0 or cmd == 1:  # ADD / MODIFY
                ins = b[off:]  # Extract flow instrucns
                port = struct.unpack("!I", ins[8 + 4:8 + 8])[0]  # Extract fst o/p port
                flows[(self.dpid, eth_dst)] = port  # Store flow rule

            elif cmd in (3, 4):  # DELETE / DELETE_STRICT
                flows.pop((self.dpid, eth_dst), None)  # Remove flow rule


# Read topology info from Ryu's REST API
def rest(path):
    return json.load(urllib.request.urlopen("http://127.0.0.1:8080/v1.0/topology/" + path, timeout=2))


# W8 until condin becomes true / timeout expires
def wait(cond, what, timeout=25):
    t0 = time.time()  # Record starting time

    while time.time() - t0 < timeout:
        try:
            if cond():
                return time.time() - t0  # Return elapsed time
        except Exception:
            pass  # Retry if condition temporarily causes an error

        time.sleep(0.1)  # Wait 100 ms before checking again

    raise AssertionError("timeout waiting for: " + what)  # Report test timeout


# Read ctrl.r's curr state from JSON file
def state():
    with open(STATE) as f:
        return json.load(f)


# Run complete end-to-end test
def main():
    env = dict(os.environ, SDN_STATE_FILE=STATE, SDN_POLICY_FILE=POLICY)    # Pass temp state & policy file paths to Ryu
    log = open(os.path.join(TMP, "ryu.log"), "w")   # Create a log file for ctrl.r o/p

    # Start the Ryu controller as a separate process
    ryu = subprocess.Popen([RYU, "--ofp-tcp-listen-port", "6653", "--observe-links",
                            "ryu.topology.switches", APP, "ryu.app.rest_topology"],
                           env=env, stdout=log, stderr=subprocess.STDOUT)

    ok = True  # Assume all tests pass initially

    try:    # W8 until Ryu starts listening on port 6653
        wait(lambda: socket.create_connection(("127.0.0.1", 6653), 1), "ryu listening", 15)

        for d in (1, 2, 3):     # Create & start 3 simulated switches
            switches[d] = FakeSwitch(d)
            switches[d].start()

        # Wait until Ryu discovers all 3 links (six directed links)
        t = wait(lambda: len(rest("links")) == 6, "LLDP link discovery (6 directed links)")
        print("PASS  Ryu discovered all 3 links through LLDP relay (%.1fs)" % t)
        # --- Hosts appear through ARP ---
        switches[1].packet_in(1, arp_frame(1, H1, "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2"))     # Simulate h1 sending an ARP rqst for h2

        # W8 until ARP flooding reaches host-facing ports of s2 & s3
        wait(lambda: {(d, tuple(p)) for d, p, _ in flood_out} >= {(2, (1,)), (3, (1,))}, "ARP flooded to edge ports")

        assert not any(d == 1 for d, _, _ in flood_out), "flooded back out of origin switch"  # Ensure ARP isn.t flooded back to originating switch

        print("PASS  unknown ARP is flooded only to host-facing ports of the other switches")

        switches[3].packet_in(1, arp_frame(2, H2, "10.0.0.2", H1, "10.0.0.1"))  # Simulate h2 replying to h1's ARP rqst

        switches[2].packet_in(1, arp_frame(1, H3, "10.0.0.3", "00:00:00:00:00:00", "10.0.0.1"))  # Simulate h3 sending an ARP rqst for h1

        wait(lambda: len(state()["hosts"]) == 3, "3 hosts learned") # Wait until ctrl.r learns all 3 hosts

        # Verify that flows towards h2 are installed on s1 & s3
        wait(lambda: flows.get((1, H2)) == 3 and flows.get((3, H2)) == 1, "flows towards h2 (direct s1-s3)")

        # Verify that the default path from h1 to h2 is s1 -> s3
        assert state()["paths"]["10.0.0.1->10.0.0.2"] == ["s1", "s3"], state()["paths"]
        print("PASS  hosts learned; flows installed; default path h1->h2 = s1-s3 (fewest hops)")

        # --- Test path pinning ---
        json.dump({"seq": 1, "pins": [[1, 2, 3], [3, 2, 1]]}, open(POLICY, "w"))    # Force traffic thru s1 -> s2 -> s3 in both direcns

        # w8 until ctrl.r applies pinned path
        wait(lambda: state()["policy_seq"] == 1 and state()["paths"]["10.0.0.1->10.0.0.2"] == ["s1", "s2", "s3"], "pinned path applied")

        assert state()["paths"]["10.0.0.2->10.0.0.1"] == ["s3", "s2", "s1"]     # Verify path from h2 to h1

        assert flows[(1, H2)] == 2 and flows[(2, H2)] == 3      # Verify that flow rules use pinned route
        print("PASS  policy pin s1-s2-s3 programmed in both directions (state file + flow tables agree)")


        # --- Test link failure and automatic rerouting ---
        t0 = time.time()  # Record failure start time

        links_up[(2, 3)] = False    # Simulate failure of the link between s2 & s3

        switches[2].port_status(3, True)    # Notify Ryu that port 3 on s2 is down

        switches[3].port_status(2, True)     # Notify Ryu that port 2 on s3 is down

        # W8 until traffic is rerouted thru s1 -> s3
        wait(lambda: state()["paths"]["10.0.0.1->10.0.0.2"] == ["s1", "s3"], "reroute after link failure")

        dt = time.time() - t0  # Calc rerouting time

        assert flows[(1, H2)] == 3       # Verify s1 fwd.s h2 traffic thru port 3
        print("PASS  link s2-s3 failed -> controller rerouted h1->h2 via s1-s3 in %.2fs" % dt)
       
        assert any("LinkDelete" in e["msg"] for e in state()["events"])  # Verify that ctrl.r recorded a link deletion event

        # --- Test failure of the last available path ---
        links_up[(1, 3)] = False    # Simulate failure of direct link b/w s1 & s3

        # Notify both switches that their connected ports are down
        switches[1].port_status(3, True)
        switches[3].port_status(3, True)

        wait(lambda: state()["paths"]["10.0.0.1->10.0.0.2"] is None, "h2 unreachable")      # Verify h1 can no longer reach h2

        wait(lambda: (1, H2) not in flows, "stale flow removed from s1")    # Verify stale flow rule is deleted from s1

        print("PASS  no route left -> path reported as None and stale flow deleted")

        # --- Restore network connectivity ---
        links_up[(2, 3)] = links_up[(1, 3)] = True      # Bring both failed links back up
        # Notify Ryu that prev.ly failed ports are active
        switches[2].port_status(3, False)
        switches[3].port_status(2, False)
        switches[1].port_status(3, False)
        switches[3].port_status(3, False)

        json.dump({"seq": 2, "pins": []}, open(POLICY, "w"))    # Clear prev.ly config.d pinned paths

        os.utime(POLICY, (time.time() + 1, time.time() + 1))    # Update policy file modification time so ctrl.r detects change

        # Wait until default shortest path is restored
        wait(lambda: state()["paths"]["10.0.0.1->10.0.0.2"] == ["s1", "s3"], "recovery after restore", 40)
        print("PASS  links restored, pins cleared -> default path back (s1-s3)")

    except AssertionError as e:
        ok = False  # Mark test as failed
        print("FAIL ", e)
        print("---- ryu log tail ----")     # Display last part of Ryu log for debugging
        log.flush()
        print(open(os.path.join(TMP, "ryu.log")).read()[-2500:])

    finally:        # Stop Ryu controller even if a test fails
        ryu.terminate()
        ryu.wait(5)


    print("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")  # Display overall test result

    sys.exit(0 if ok else 1) # Exit with status 0 for success, 1 for failure


if __name__ == "__main__":
    main()