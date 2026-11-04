#!/usr/bin/env python3
"""
Tests for dynamic_path_app.py without Mininet: fake switches built from Ryu's real
OpenFlow 1.3 message classes.  Run with the Python that has Ryu installed:
    .venv-ryu/bin/python tests/test_dynamic_app.py
"""

import json, os, sys, tempfile, types, unittest

TMP = tempfile.mkdtemp()    # Create temp storage for policy & ctrl.r state files

# Redirect app's policy & state files to temp dir
os.environ["SDN_POLICY_FILE"] = os.path.join(TMP, "policy.json")
os.environ["SDN_STATE_FILE"] = os.path.join(TMP, "state.json")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))      # Add project root to Python's module search path

from ryu.lib.packet import arp, ethernet, ether_types, ipv4, packet
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
import dynamic_path_app as app_mod
from dynamic_path_app import DynamicPathApp, PathEngine

H1, H2, H3 = "00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03"  # MAC addr assigned to 3 simulated hosts


# Simulate an OpenFlow switch (datapath) without running a real switch
class FakeDP:
    ofproto, ofproto_parser = ofproto_v1_3, ofproto_v1_3_parser     # Use Ryu's actual OpenFlow 1.3 protocol & parser definitions
    def __init__(self, i):
        self.id, self.sent = i, []  # Store switch ID & msgs sent to it

    def send_msg(self, m):
        self.sent.append(m)  # Record msgs instead of sending them to a real switch


# Create a directed link b/w 2 switches
def link(a, ap, b, bp):
    return types.SimpleNamespace(src=types.SimpleNamespace(dpid=a, port_no=ap), dst=types.SimpleNamespace(dpid=b, port_no=bp))


# Mn-style port no.ing for 3-switch triangle topology
# Each switch has 1 host-facing port & 2 inter-switch ports
TRIANGLE = [(1, 2, 2, 2), (2, 3, 3, 2), (1, 3, 3, 3)]


# Conv list of links into both fwd & rev dircns
def both(pairs):
    out = []

    for a, ap, b, bp in pairs:
        out += [link(a, ap, b, bp), link(b, bp, a, ap)]

    return out


# Construct ARP pkt for testing host discovery & ARP handling
def arp_pkt(op, smac, sip, dmac, dip):
    p = packet.Packet()     # Create an empty pkt

    dst = "ff:ff:ff:ff:ff:ff" if op == arp.ARP_REQUEST else dmac    # ARP rqsts use broadcast; replies use dest MAC

    p.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, dst=dst, src=smac))    # Add Ethernet header w/ ARP as payload type

    # Add the ARP request or reply details
    p.add_protocol(arp.arp(opcode=op, src_mac=smac, src_ip=sip, dst_mac="00:00:00:00:00:00" if op == arp.ARP_REQUEST else dmac, dst_ip=dip))

    p.serialize()   # Serialize pkt into bytes

    return p.data  # Return raw packet data


# Construct an IPv4 pkt for testing fwding behaviour
def ip_pkt(smac, sip, dmac, dip):
    p = packet.Packet()     # Create an empty packet
    # Add Ethernet header w/ IPv4 as its payload type
    p.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP, dst=dmac, src=smac))
    p.add_protocol(ipv4.ipv4(src=sip, dst=dip, proto=17))   # Add IPv4 header; protocol 17 represents UDP
    p.serialize()   # Serialize pkt into bytes
    return p.data  # Return raw pkt data


# Create simulated Packet-In event received by ctrl.r 
def pin_event(dp, in_port, data):
    # Build OpenFlow Packet-In msg containing incoming port & pkt
    msg = ofproto_v1_3_parser.OFPPacketIn(datapath=dp, match=ofproto_v1_3_parser.OFPMatch(in_port=in_port), data=data)
    return types.SimpleNamespace(msg=msg)   # Wrap msg in an event-like obj expected by app


# Common test setup shared by app test cases
class Base(unittest.TestCase):

    def make_app(self, pairs=TRIANGLE):
        self.links = both(pairs)    # Create bidirectional links for simulated topology

        app_mod.get_link = lambda *a, **k: self.links    # Replace Ryu's topology link discovery w/ our simulated links

        ports = {1: [1, 2, 3], 2: [1, 2, 3], 3: [1, 2, 3]}      # Define avail ports on each of 3 switches

        # Replace Ryu's switch discovery w/ simulated switch info
        app_mod.get_switch = lambda *a, **k: [
            types.SimpleNamespace(dp=types.SimpleNamespace(id=d), ports=[types.SimpleNamespace(port_no=p) for p in ps]) for d, ps in ports.items()]

        # Remove old test files so each test starts w/ clean state
        for f in (os.environ["SDN_POLICY_FILE"], os.environ["SDN_STATE_FILE"]):
            if os.path.exists(f):
                os.remove(f)

        app = DynamicPathApp()      # Create fresh instance of SDN app
        app._policy_mtime = None    # Reset policy-file modification tracking
        app.dps = {i: FakeDP(i) for i in (1, 2, 3)}     # Attach 3 fake switches to app
        app._refresh_topology()     # Make app discover simulated topology
        return app


    @staticmethod
    def flows(dp):
        """Return (priority, destination MAC, output port) for every added flow."""
        out = []
        for m in dp.sent:   # Examine every msg sent to switch
            # Select only flow-modification msgs that add flows
            if isinstance(m, ofproto_v1_3_parser.OFPFlowMod) and m.command == 0:
                d = m.match.to_jsondict()["OFPMatch"]["oxm_fields"] # Extract match fields from OpenFlow match struc
                eth = next((f["OXMTlv"]["value"] for f in d if f["OXMTlv"]["field"] == "eth_dst"), None)    # Find dest MAC addr matched
                act = m.instructions[0].actions[0].port     # Extract o/p port from fst flow action
                out.append((m.priority, eth, act))      # Store flow priority, dest MAC & o/p port
        return out


    def learn_all(self, app):
        """Simulate ARP exchanges so the controller learns all three hosts."""
        app._packet_in(pin_event(app.dps[1], 1, arp_pkt(arp.ARP_REQUEST, H1, "10.0.0.1", "", "10.0.0.2"))) # h1 broadcasts ARP rqst asking for h2
        app._packet_in(pin_event(app.dps[3], 1, arp_pkt(arp.ARP_REPLY, H2, "10.0.0.2", H1, "10.0.0.1")))    # h2 sends ARP reply to h1
        app._packet_in(pin_event(app.dps[2], 1, arp_pkt(arp.ARP_REQUEST, H3, "10.0.0.3", "", "10.0.0.1"))) # h3 sends ARP rqst, allowing ctrl.r to learn h3


# Test the path calculation engine independently of the controller application
class TestEngine(unittest.TestCase):

    def test_default_pin_and_failover(self):
        e = PathEngine()     # Create path calc engine
        # Config the three-switch triangle topology
        e.set_links([(a, ap, b, bp) for a, ap, b, bp in [(1, 2, 2, 2), (2, 2, 1, 2), (2, 3, 3, 2), (3, 2, 2, 3), (1, 3, 3, 3), (3, 3, 1, 3)]])
        # Calc routes from s1 to s3
        out = e.routes_to(3, 1)

        self.assertEqual(e.trace(1, 3, out), [1, 3])  # Verify that default route uses direct, 1-hop link
        out = e.routes_to(3, 1, pins=[[1, 2, 3]])   # Apply pinned route that forces traffic thru s2
        self.assertEqual(e.trace(1, 3, out), [1, 2, 3])     # Verify that pinned 2-hop route is selected
        e.set_links([(1, 2, 2, 2), (2, 2, 1, 2), (2, 3, 3, 2), (3, 2, 2, 3)])    # Remove direct link b/w s1 & s3
        self.assertEqual(e.trace(1, 3, e.routes_to(3, 1)), [1, 2, 3])   # Verify that routing automatically uses alt path
        self.assertEqual(e.trace(1, 3, e.routes_to(3, 1, pins=[[1, 3]])), [1, 2, 3])  # pin using a missing link is ignored; avail route used
        e.set_links([(1, 2, 2, 2), (2, 2, 1, 2)])   # Remove s2-s3 link as well, making s3 unreachable
        self.assertIsNone(e.trace(1, 3, e.routes_to(3, 1))) # Verify that no route exists


    def test_bad_pins_ignored(self):
        # Create a path engine w/ only s1-s2 connection
        e = PathEngine()
        e.set_links([(1, 2, 2, 2), (2, 2, 1, 2)])

        # Test invalid pins: too short / looping / wrong destination / unknown switch
        for pin in ([1], [1, 2, 1, 2], [2, 1], [5, 2]):
            out = e.routes_to(2, 1, pins=[pin])
            self.assertEqual(e.trace(1, 2, out), [1, 2])    # Invalid pins must be ignored in favour of valid default route


# Test complete SDN app behaviour using fake switches
class TestApp(Base):

    def test_arp_flood_only_on_edge_ports(self):
        app = self.make_app()   #  Create app simulated topology
        app._packet_in(pin_event(app.dps[1], 1, arp_pkt(arp.ARP_REQUEST, H1, "10.0.0.1", "", "10.0.0.2")))  # Simulate h1 sending ARP rqst

        # Collect Packet-Out msgs sent by each switch
        sent = {i: [m for m in dp.sent if isinstance(m, ofproto_v1_3_parser.OFPPacketOut)] for i, dp in app.dps.items()}

        self.assertEqual(sent[1], [])   # Originating switch has no oth. eligible edge port

        self.assertEqual([a.port for a in sent[2][0].actions], [1])   # s2 floods ARP rqst only thru its host-facing port
        self.assertEqual([a.port for a in sent[3][0].actions], [1])   # s3 also floods only thru its host-facing port

    # Create app & simulate all hosts being discovered
    def test_learn_install_and_proxy_arp(self):
        app = self.make_app()
        self.learn_all(app)

        self.assertEqual(set(app.hosts), {H1, H2, H3})      # Verify that all 3 host MAC addr.s were learned

        f1 = {(p, e): o for p, e, o in self.flows(app.dps[1])}  # Extract flows installed on s1

        self.assertEqual(f1[(5, H2)], 3)    # Traffic going to h2 leaves s1 thru port 3 (direct link to s3)
        self.assertEqual(f1[(5, H1)], 1)    # Traffic going to h1 leaves s1 thru its local host port

        f3 = {(p, e): o for p, e, o in self.flows(app.dps[3])}  # Extract flows installed on s3

        self.assertEqual(f3[(5, H2)], 1)    # h2 is directly connected to s3 thru port 1

        self.assertEqual(f3[(5, H1)], 3)    # Traffic towards h1 leaves s3 thru port 3

        app.dps[1].sent.clear()      # Test proxy ARP: h1 asks for h2 again after ctrl.r has learned both
        app._packet_in(pin_event(app.dps[1], 1, arp_pkt(arp.ARP_REQUEST, H1, "10.0.0.1", "", "10.0.0.2")))

        po = [m for m in app.dps[1].sent if isinstance(m, ofproto_v1_3_parser.OFPPacketOut)]    # Collect Packet-Out msgs gen.d by ctrl.r's ARP reply
        self.assertEqual(len(po), 1)    # Exactly 1 Packet-Out should contain proxy ARP reply
        reply = packet.Packet(po[0].data).get_protocol(arp.arp)  # Decode gen.d pkt & extract its ARP header

        # Verify reply contains expected sender & dest info
        self.assertEqual((reply.opcode, reply.src_mac, reply.src_ip, reply.dst_mac), (arp.ARP_REPLY, H2, "10.0.0.2", H1))
        # Verify reply is sent back thru h1's incoming port
        self.assertEqual(po[0].actions[0].port, 1)


    def test_reroute_on_link_failure(self):
        # Create the app & learn all hosts
        app = self.make_app()
        self.learn_all(app)

        self.assertEqual(app.engine.trace(1, 3, app.routes[H2]), [1, 3])     # Confirm h2 is init.ly reached thu direct s1-s3 path

        for dp in app.dps.values(): # Clear prev.ly recorded msgs from all fake switches
            dp.sent.clear()

        self.links = both([p for p in TRIANGLE if p[:3:2] != (1, 3)])   # Remove direct s1-s3 connection from simulated topology
        app._deferred_reroute()     # Trigger app's rerouting procedure
        self.assertEqual(app.engine.trace(1, 3, app.routes[H2]), [1, 2, 3])     # Verify that traffic now travels thru s2

        f1 = {(p, e): o for p, e, o in self.flows(app.dps[1])}  # Extract updated flows installed on s1
        self.assertEqual(f1[(5, H2)], 2)    # Verify s1 now fwds traffic to s2 thru port 2

        st = json.load(open(os.environ["SDN_STATE_FILE"]))    # Read ctrl.r's updated state file

        self.assertEqual(st["paths"]["10.0.0.1->10.0.0.2"], ["s1", "s2", "s3"])     # Verify saved route reflects new path

        # Verify that flow-reinstallation event was recorded
        self.assertTrue(any("flows reinstalled" in e["msg"] for e in st["events"]))


    def test_pin_via_policy_file_and_fallback(self):
        # Create the application and learn all hosts
        app = self.make_app()
        self.learn_all(app)

        # Write a policy that pins traffic thru s1 -> s2 -> s3 in both directions
        json.dump({"seq": 7, "pins": [[1, 2, 3], [3, 2, 1]]}, open(os.environ["SDN_POLICY_FILE"], "w"))

        self.assertTrue(app._poll_policy_once())    # Read & apply new policy from file
        self.assertFalse(app._poll_policy_once())   # An unchanged policy file shouldn't trigger another update

        st = json.load(open(os.environ["SDN_STATE_FILE"]))  # Read ctrl.r's curr state
        self.assertEqual(st["policy_seq"], 7)   # Verify policy seq no. was recorded

        self.assertEqual(st["paths"]["10.0.0.1->10.0.0.2"], ["s1", "s2", "s3"])     # Verify fwd.ing route follows pinned path  
        self.assertEqual(st["paths"]["10.0.0.2->10.0.0.1"], ["s3", "s2", "s1"])     # Verify reverse route follows reverse pinned path

        self.links = both([(1, 2, 2, 2), (1, 3, 3, 3)])     # Simulate failure of s2-s3 link while pinned path is active

        app._deferred_reroute()     # Trigger rerouting, invalid pin should be ignored

        self.assertEqual(app.engine.trace(1, 3, app.routes[H2]), [1, 3])    # remaining valid route is direct s1-s3 path
        self.links = both(TRIANGLE)     # Restore OG triangle topology
        app._deferred_reroute()     # Recalc routes using restored topology
        json.dump({"seq": 8, "pins": []}, open(os.environ["SDN_POLICY_FILE"], "w"))   # Write a new policy w/ no pinned paths
        os.utime(os.environ["SDN_POLICY_FILE"], (1, 12345))   # Set modification time so app detects policy update

        self.assertTrue(app._poll_policy_once())    # Apply updated policy
        self.assertEqual(app.engine.trace(1, 3, app.routes[H2]), [1, 3])    # Verify routing ret.s to default direct path


    def test_unreachable_host_flows_removed(self):
        # Create app & learn all hosts
        app = self.make_app()
        self.learn_all(app)

        self.links = both([(1, 2, 2, 2)])    # Simulate a topology where s3 becomes isolated

        app._deferred_reroute()      # Trigger route recalculation after topology change

        self.assertNotIn(3, app.routes[H1] if 3 in app.routes[H1] else [])  # Verify s3 is no longer present in h1's route
        self.assertIsNone(app.engine.trace(1, 3, app.routes[H2]))   # Verify that h2 is now unreachable from s1
        
        # Find strict flow-deletion msgs sent to s1
        dels = [m for m in app.dps[1].sent if isinstance(m, ofproto_v1_3_parser.OFPFlowMod) and m.command == ofproto_v1_3.OFPFC_DELETE_STRICT]

        self.assertTrue(dels)   # Verify that stale fwding rules were deleted


    def test_ip_forwarding_and_unknown_dst(self):
        # Create the application and learn all hosts
        app = self.make_app()
        self.learn_all(app)

        app.dps[1].sent.clear()     # Clear existing msgs b4 testing IP fwding

        app._packet_in(pin_event(app.dps[1], 1, ip_pkt(H1, "10.0.0.1", H2, "10.0.0.2")))    # Simulate IPv4 pkt arriving @ s1 from h1
        po = [m for m in app.dps[1].sent if isinstance(m, ofproto_v1_3_parser.OFPPacketOut)]    # Collect Packet-Out msgs gen.d by ctrl.r
        self.assertEqual([m.actions[0].port for m in po], [3])  # Verify pkt is fwding thru port 3 towards s3

        app.dps[1].sent.clear()     # Clear msgs b4 testing an unknown dest

        # Simulate a pkt addressed to an unknown host
        app._packet_in(pin_event(app.dps[1], 1, ip_pkt(H1, "10.0.0.1", "00:00:00:00:00:99", "10.0.0.99")))

        self.assertEqual(app.dps[1].sent, [])   # Verify that no fwd.ing msg is gen.d for unknown dest


    def test_no_learning_on_link_port_and_arp_probe(self):
        # Create app
        app = self.make_app()
        # Simulate ARP pkt arriving on port 2, which connects to another switch
        app._packet_in(pin_event(app.dps[1], 2, arp_pkt(arp.ARP_REQUEST, H3, "10.0.0.3", "", "10.0.0.1")))
        # Simulate ARP probe w/ src IP 0.0.0.0
        app._packet_in(pin_event(app.dps[1], 1, arp_pkt(arp.ARP_REQUEST, H1, "0.0.0.0", "", "10.0.0.1")))
        self.assertEqual(app.hosts, {})     # Neither pkt should cause a host to be learned


    def test_malformed_packet_does_not_crash(self):
        # Create app
        app = self.make_app()
        app._packet_in(pin_event(app.dps[1], 1, b"\x00\x01garbage"))    # Send malformed pkt data & verify handler doesn't crash


if __name__ == "__main__":
    unittest.main(verbosity=2)