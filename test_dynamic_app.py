#!/usr/bin/env python3
# Unit/integration-style tests for the Ryu app without launching Mininet.
# Fake datapaths record OpenFlow messages, allowing assertions about routes,
# ARP handling and flow installation while using Ryu's real message classes.
"""
Tests for dynamic_path_app.py without Mininet: fake switches built from Ryu's real
OpenFlow 1.3 message classes.  Run with the Python that has Ryu installed:
    .venv-ryu/bin/python tests/test_dynamic_app.py
"""
import json, os, sys, tempfile, types, unittest

TMP = tempfile.mkdtemp()
os.environ["SDN_POLICY_FILE"] = os.path.join(TMP, "policy.json")
os.environ["SDN_STATE_FILE"] = os.path.join(TMP, "state.json")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ryu.lib.packet import arp, ethernet, ether_types, ipv4, packet
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
import dynamic_path_app as app_mod
from dynamic_path_app import DynamicPathApp, PathEngine

H1, H2, H3 = "00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03"


class FakeDP:
     # A lightweight stand-in for an OpenFlow switch connection. Instead of
    # transmitting messages over a socket, it stores them in the sent list.
    ofproto, ofproto_parser = ofproto_v1_3, ofproto_v1_3_parser

    def __init__(self, i):
        self.id, self.sent = i, []

    def send_msg(self, m):
        self.sent.append(m)


def link(a, ap, b, bp):
    # Create an object shaped like a Ryu discovered link: source DPID/port
    # and destination DPID/port. DPID is the numeric switch identifier.
    return types.SimpleNamespace(src=types.SimpleNamespace(dpid=a, port_no=ap),
                                 dst=types.SimpleNamespace(dpid=b, port_no=bp))


# Mininet-style numbering. s1:1=h1 2=s2 3=s3   s2:1=h3 2=s1 3=s3   s3:1=h2 2=s2 3=s1
TRIANGLE = [(1, 2, 2, 2), (2, 3, 3, 2), (1, 3, 3, 3)]


def both(pairs):
    # Ryu reports each direction separately, so turn each physical link into
    # two directed link records (A->B and B->A).
    out = []
    for a, ap, b, bp in pairs:
        out += [link(a, ap, b, bp), link(b, bp, a, ap)]
    return out


def arp_pkt(op, smac, sip, dmac, dip):
    # Build a real serialized Ethernet + ARP frame for the controller handler.
    # This lets tests exercise packet parsing, not just call helper functions.
    p = packet.Packet()
    dst = "ff:ff:ff:ff:ff:ff" if op == arp.ARP_REQUEST else dmac
    p.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, dst=dst, src=smac))
    p.add_protocol(arp.arp(opcode=op, src_mac=smac, src_ip=sip,
                           dst_mac="00:00:00:00:00:00" if op == arp.ARP_REQUEST else dmac,
                           dst_ip=dip))
    p.serialize()
    return p.data


def ip_pkt(smac, sip, dmac, dip):
    p = packet.Packet()
    p.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP, dst=dmac, src=smac))
    p.add_protocol(ipv4.ipv4(src=sip, dst=dip, proto=17))
    p.serialize()
    return p.data


def pin_event(dp, in_port, data):
    msg = ofproto_v1_3_parser.OFPPacketIn(datapath=dp, match=ofproto_v1_3_parser.OFPMatch(in_port=in_port), data=data)
    return types.SimpleNamespace(msg=msg)


class Base(unittest.TestCase):
     # Shared setup used by controller tests: fake topology discovery, temporary
    # policy/state files, fake switches, and a helper to teach the app all hosts.
    def make_app(self, pairs=TRIANGLE):
        self.links = both(pairs)
        app_mod.get_link = lambda *a, **k: self.links
        ports = {1: [1, 2, 3], 2: [1, 2, 3], 3: [1, 2, 3]}
        app_mod.get_switch = lambda *a, **k: [
            types.SimpleNamespace(dp=types.SimpleNamespace(id=d),
                                  ports=[types.SimpleNamespace(port_no=p) for p in ps])
            for d, ps in ports.items()]
        for f in (os.environ["SDN_POLICY_FILE"], os.environ["SDN_STATE_FILE"]):
            if os.path.exists(f):
                os.remove(f)
        app = DynamicPathApp()
        app._policy_mtime = None
        app.dps = {i: FakeDP(i) for i in (1, 2, 3)}
        app._refresh_topology()
        return app

    @staticmethod
    def flows(dp):
        """(priority, eth_dst, out_port) of every ADD flow-mod sent to this switch."""
        out = []
        for m in dp.sent:
            if isinstance(m, ofproto_v1_3_parser.OFPFlowMod) and m.command == 0:
                d = m.match.to_jsondict()["OFPMatch"]["oxm_fields"]
                eth = next((f["OXMTlv"]["value"] for f in d if f["OXMTlv"]["field"] == "eth_dst"), None)
                act = m.instructions[0].actions[0].port
                out.append((m.priority, eth, act))
        return out

    def learn_all(self, app):
        """h1 ARPs for h2 (flooded), h2 replies; also h3 joins."""
        app._packet_in(pin_event(app.dps[1], 1, arp_pkt(arp.ARP_REQUEST, H1, "10.0.0.1", "", "10.0.0.2")))
        app._packet_in(pin_event(app.dps[3], 1, arp_pkt(arp.ARP_REPLY, H2, "10.0.0.2", H1, "10.0.0.1")))
        app._packet_in(pin_event(app.dps[2], 1, arp_pkt(arp.ARP_REQUEST, H3, "10.0.0.3", "", "10.0.0.1")))


class TestEngine(unittest.TestCase):
     # Tests the graph algorithm independently of Ryu: shortest path, valid
    # dashboard pins, ignoring invalid pins, and unreachable destinations.
    def test_default_pin_and_failover(self):
        e = PathEngine()
        e.set_links([(a, ap, b, bp) for a, ap, b, bp in
                     [(1, 2, 2, 2), (2, 2, 1, 2), (2, 3, 3, 2), (3, 2, 2, 3), (1, 3, 3, 3), (3, 3, 1, 3)]])
        out = e.routes_to(3, 1)
        self.assertEqual(e.trace(1, 3, out), [1, 3])                 # fewest hops = direct link
        out = e.routes_to(3, 1, pins=[[1, 2, 3]])
        self.assertEqual(e.trace(1, 3, out), [1, 2, 3])              # pin forces the 2-hop path
        e.set_links([(1, 2, 2, 2), (2, 2, 1, 2), (2, 3, 3, 2), (3, 2, 2, 3)])   # s1-s3 down
        self.assertEqual(e.trace(1, 3, e.routes_to(3, 1)), [1, 2, 3])
        # pin over a missing link is ignored (falls back to default)
        self.assertEqual(e.trace(1, 3, e.routes_to(3, 1, pins=[[1, 3]])), [1, 2, 3])
        e.set_links([(1, 2, 2, 2), (2, 2, 1, 2)])                    # s2-s3 also down -> unreachable
        self.assertIsNone(e.trace(1, 3, e.routes_to(3, 1)))

    def test_bad_pins_ignored(self):
        e = PathEngine()
        e.set_links([(1, 2, 2, 2), (2, 2, 1, 2)])
        for pin in ([1], [1, 2, 1, 2], [2, 1], [5, 2]):              # too short / loop / wrong dest / unknown
            out = e.routes_to(2, 1, pins=[pin])
            self.assertEqual(e.trace(1, 2, out), [1, 2])


class TestApp(Base):
    # Tests the full controller behaviour using fake switches: ARP, host learning,
    # flow rules, link failure rerouting, policy pins and malformed packets.
    def test_arp_flood_only_on_edge_ports(self):
        app = self.make_app()
        app._packet_in(pin_event(app.dps[1], 1, arp_pkt(arp.ARP_REQUEST, H1, "10.0.0.1", "", "10.0.0.2")))
        sent = {i: [m for m in dp.sent if isinstance(m, ofproto_v1_3_parser.OFPPacketOut)] for i, dp in app.dps.items()}
        self.assertEqual(sent[1], [])                                  # origin port excluded, others are links
        self.assertEqual([a.port for a in sent[2][0].actions], [1])    # s2 edge port only (h3)
        self.assertEqual([a.port for a in sent[3][0].actions], [1])    # s3 edge port only (h2)

    def test_learn_install_and_proxy_arp(self):
        app = self.make_app()
        self.learn_all(app)
        self.assertEqual(set(app.hosts), {H1, H2, H3})
        f1 = {(p, e): o for p, e, o in self.flows(app.dps[1])}
        self.assertEqual(f1[(5, H2)], 3)                               # s1 -> h2 via direct s1-s3 link (port 3)
        self.assertEqual(f1[(5, H1)], 1)                               # s1 -> h1 local port
        f3 = {(p, e): o for p, e, o in self.flows(app.dps[3])}
        self.assertEqual(f3[(5, H2)], 1)
        self.assertEqual(f3[(5, H1)], 3)
        # proxy ARP: h1 asks for h2 again -> controller answers on the same port
        app.dps[1].sent.clear()
        app._packet_in(pin_event(app.dps[1], 1, arp_pkt(arp.ARP_REQUEST, H1, "10.0.0.1", "", "10.0.0.2")))
        po = [m for m in app.dps[1].sent if isinstance(m, ofproto_v1_3_parser.OFPPacketOut)]
        self.assertEqual(len(po), 1)
        reply = packet.Packet(po[0].data).get_protocol(arp.arp)
        self.assertEqual((reply.opcode, reply.src_mac, reply.src_ip, reply.dst_mac), (arp.ARP_REPLY, H2, "10.0.0.2", H1))
        self.assertEqual(po[0].actions[0].port, 1)

    def test_reroute_on_link_failure(self):
        # Remove the direct s1-s3 link. The controller must recalculate the
        # route to h2 through s1-s2-s3 and change s1's output port accordingly.
        app = self.make_app()
        self.learn_all(app)
        self.assertEqual(app.engine.trace(1, 3, app.routes[H2]), [1, 3])
        for dp in app.dps.values():
            dp.sent.clear()
        self.links = both([p for p in TRIANGLE if p[:3:2] != (1, 3)])   # s1-s3 disappears
        app._deferred_reroute()
        self.assertEqual(app.engine.trace(1, 3, app.routes[H2]), [1, 2, 3])
        f1 = {(p, e): o for p, e, o in self.flows(app.dps[1])}
        self.assertEqual(f1[(5, H2)], 2)                               # s1 now sends to s2 (port 2)
        st = json.load(open(os.environ["SDN_STATE_FILE"]))
        self.assertEqual(st["paths"]["10.0.0.1->10.0.0.2"], ["s1", "s2", "s3"])
        self.assertTrue(any("flows reinstalled" in e["msg"] for e in st["events"]))

    def test_pin_via_policy_file_and_fallback(self):
        app = self.make_app()
        self.learn_all(app)
        json.dump({"seq": 7, "pins": [[1, 2, 3], [3, 2, 1]]}, open(os.environ["SDN_POLICY_FILE"], "w"))
        self.assertTrue(app._poll_policy_once())
        self.assertFalse(app._poll_policy_once())                      # unchanged file -> nothing to do
        st = json.load(open(os.environ["SDN_STATE_FILE"]))
        self.assertEqual(st["policy_seq"], 7)
        self.assertEqual(st["paths"]["10.0.0.1->10.0.0.2"], ["s1", "s2", "s3"])
        self.assertEqual(st["paths"]["10.0.0.2->10.0.0.1"], ["s3", "s2", "s1"])
        # pinned link goes down -> pin ignored -> default path of the remaining topology
        self.links = both([(1, 2, 2, 2), (1, 3, 3, 3)])                # s2-s3 down
        app._deferred_reroute()
        self.assertEqual(app.engine.trace(1, 3, app.routes[H2]), [1, 3])
        # clearing the policy returns to shortest-hop routing
        self.links = both(TRIANGLE)
        app._deferred_reroute()
        json.dump({"seq": 8, "pins": []}, open(os.environ["SDN_POLICY_FILE"], "w"))
        os.utime(os.environ["SDN_POLICY_FILE"], (1, 12345))
        self.assertTrue(app._poll_policy_once())
        self.assertEqual(app.engine.trace(1, 3, app.routes[H2]), [1, 3])

    def test_unreachable_host_flows_removed(self):
        # Disconnect s3 from the rest of the graph. Verify there is no route
        # to h2 and that the old destination flow is deleted from s1.
        app = self.make_app()
        self.learn_all(app)
        self.links = both([(1, 2, 2, 2)])                              # s3 isolated
        app._deferred_reroute()
        self.assertNotIn(3, app.routes[H1] if 3 in app.routes[H1] else [])
        self.assertIsNone(app.engine.trace(1, 3, app.routes[H2]))
        dels = [m for m in app.dps[1].sent if isinstance(m, ofproto_v1_3_parser.OFPFlowMod)
                and m.command == ofproto_v1_3.OFPFC_DELETE_STRICT]
        self.assertTrue(dels)                                          # stale flow towards h2 deleted on s1

    def test_ip_forwarding_and_unknown_dst(self):
        app = self.make_app()
        self.learn_all(app)
        app.dps[1].sent.clear()
        app._packet_in(pin_event(app.dps[1], 1, ip_pkt(H1, "10.0.0.1", H2, "10.0.0.2")))
        po = [m for m in app.dps[1].sent if isinstance(m, ofproto_v1_3_parser.OFPPacketOut)]
        self.assertEqual([m.actions[0].port for m in po], [3])
        app.dps[1].sent.clear()
        app._packet_in(pin_event(app.dps[1], 1, ip_pkt(H1, "10.0.0.1", "00:00:00:00:00:99", "10.0.0.99")))
        self.assertEqual(app.dps[1].sent, [])                          # unknown destination: dropped

    def test_no_learning_on_link_port_and_arp_probe(self):
        app = self.make_app()
        app._packet_in(pin_event(app.dps[1], 2, arp_pkt(arp.ARP_REQUEST, H3, "10.0.0.3", "", "10.0.0.1")))   # port 2 = link
        app._packet_in(pin_event(app.dps[1], 1, arp_pkt(arp.ARP_REQUEST, H1, "0.0.0.0", "", "10.0.0.1")))    # ARP probe
        self.assertEqual(app.hosts, {})

    def test_malformed_packet_does_not_crash(self):
        app = self.make_app()
        app._packet_in(pin_event(app.dps[1], 1, b"\x00\x01garbage"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
