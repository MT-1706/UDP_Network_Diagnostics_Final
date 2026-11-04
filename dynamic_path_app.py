#!/usr/bin/env python3
"""
Dynamic path controller - a Ryu application (OpenFlow 1.3).

What it does (this is the "Dynamic SDN" part of the project):
  * Learns hosts from ARP and answers ARP itself (proxy ARP), so the network can
    contain loops (the s1-s3 link) without broadcast storms.  Unknown ARP
    requests are flooded ONLY out of host-facing (edge) ports.
  * Computes a shortest-hop path to every host and INSTALLS flow rules
    (match eth_dst -> output port) on every switch.
  * REROUTES automatically: when the topology module reports a link/switch
    added or removed, flows are recomputed and re-installed.
  * Accepts PATH PINS from the dashboard through a small JSON file, so a
    specific path can be forced (used to measure every alternative path, and to
    apply the best measured path).  A pin whose links are down is ignored, so the
    network falls back to the default shortest path by itself.
  * Exports its real routing state (hosts, links, installed paths, an event log
    with timestamps) to a JSON file that the dashboard reads, so the path shown
    on the dashboard is the one the controller programmed, not a guess.

Run (Ryu from your virtualenv, no sudo):
  .venv-ryu/bin/ryu-manager --ofp-tcp-listen-port 6653 --observe-links \
      ryu.topology.switches dynamic_path_app.py ryu.app.rest_topology

Do NOT also load ryu.app.simple_switch_13 - this app replaces it.
"""
import json
import os
import time
from collections import deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                    MAIN_DISPATCHER, set_ev_cls)
from ryu.lib import hub
from ryu.lib.packet import arp, ethernet, ether_types, ipv4, packet
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_link, get_switch

POLICY_FILE = os.environ.get("SDN_POLICY_FILE", "/tmp/sdn_policy.json")
STATE_FILE = os.environ.get("SDN_STATE_FILE", "/tmp/sdn_state.json")

PRIO_ARP = 10          # ARP always goes to the controller
PRIO_HOST = 5          # eth_dst -> port flows
PRIO_MISS = 0          # table-miss
DEBOUNCE_S = 0.02      # wait this long after a topology event before rerouting (merges the 2 events one link failure causes)
MAX_EVENTS = 60


# ===========================================================================
# Pure routing logic (no Ryu objects) - unit tested separately
# ===========================================================================
class PathEngine:
  # This is the routing/graph logic, kept separate from Ryu so it can
    # be unit-tested without creating real switches or sending OpenFlow messages.
    """Graph of switches built from discovered links, plus routing helpers."""

    def __init__(self):
        self.adj = {}      # dpid -> {neighbour dpid: out port towards it}
        self.port_nb = {}  # dpid -> {out port: neighbour dpid}

    def set_links(self, links):
     # Build two lookup tables from Ryu's discovered links:
        # adj answers "which switches neighbour this switch?"; port_nb answers
        # "which neighbour is reached through this output port?".
        """links: iterable of (src_dpid, src_port, dst_dpid, dst_port)."""
        adj, pnb = {}, {}
        for sd, sp, dd, _dp in links:
            adj.setdefault(sd, {}).setdefault(dd, sp)   # first link wins if parallel
            pnb.setdefault(sd, {})[sp] = dd
        self.adj, self.port_nb = adj, pnb

    def is_link_port(self, dpid, port):
        return port in self.port_nb.get(dpid, {})

    def routes_to(self, dst_dpid, dst_port, pins=()):
     # Breadth-first search (BFS), starting at the destination switch.
        # BFS finds a route with the fewest switch-to-switch hops. For each
        # switch it records the output port that moves packets closer to dst.
        # A valid dashboard pin can override the default next-hop choices.
        """
        Output port on every switch for traffic destined to a host that hangs
        off (dst_dpid, dst_port).  Default = fewest hops (BFS, ties broken by
        lowest dpid).  Valid pins override the next hop along the pinned path.
        """
        out = {dst_dpid: dst_port}
        q = deque([dst_dpid])
        while q:
            m = q.popleft()
            for n in sorted(self.adj.get(m, {})):
                if n in out:
                    continue
                p = self.adj.get(n, {}).get(m)      # n's port towards m
                if p is None:
                    continue
                out[n] = p
                q.append(n)
        for pin in pins:
            self._apply_pin(out, dst_dpid, pin)
        return out

    def _apply_pin(self, out, dst_dpid, pin):
     # A pin is a requested switch sequence, e.g. [s1, s2, s3]. Reject
        # malformed paths, loops, wrong destinations, or paths containing a
        # missing link. Validate the WHOLE path before changing output ports.
        """Apply one pinned path; ignore it entirely if any link is missing."""
        pin = list(pin)
        if len(pin) < 2 or pin[-1] != dst_dpid or len(set(pin)) != len(pin):
            return False
        ports = []
        for a, b in zip(pin, pin[1:]):
            p = self.adj.get(a, {}).get(b)
            if p is None:                            # link down -> pin is void
                return False
            ports.append(p)
        for a, p in zip(pin, ports):
            out[a] = p
        return True

    def trace(self, src_dpid, dst_dpid, out):
     # Follow the output-port decisions to reconstruct the actual route.
        # Return None if a port has no neighbour or if a loop is detected.
        """Follow the programmed next hops; return the switch path or None."""
        path, cur = [src_dpid], src_dpid
        while cur != dst_dpid:
            nxt = self.port_nb.get(cur, {}).get(out.get(cur))
            if nxt is None or nxt in path:
                return None
            path.append(nxt)
            cur = nxt
        return path


def _atomic_write(path, obj):
 # Write JSON to a temporary file first, then replace the old file in one
    # operation. The dashboard therefore avoids reading a half-written state.
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def sname(dpid):
    return "s%d" % dpid


# ===========================================================================
# Ryu application
# ===========================================================================
class DynamicPathApp(app_manager.RyuApp):
  # This is the actual Ryu controller application. It converts the
    # routes calculated by PathEngine into OpenFlow rules installed on switches.
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
     # Keep track of connected switches, learned hosts, routes, installed
        # flows, dashboard path pins and recent controller events
        super(DynamicPathApp, self).__init__(*args, **kwargs)
        self.engine = PathEngine()
        self.dps = {}              # dpid -> datapath
        self.switch_ports = {}     # dpid -> [port numbers]
        self.hosts = {}            # mac -> {"ip","mac","dpid","port"}
        self.ip_to_mac = {}
        self.routes = {}           # mac -> {dpid: out port} (what we programmed)
        self.installed = {}        # mac -> set(dpid) that currently hold a flow
        self.pins = []             # list of pinned paths (lists of dpids)
        self.policy_seq = 0
        self.event_log = []        # NB: not 'events' - that name belongs to Ryu's RyuApp
        self._pending = False
        hub.spawn(self._policy_loop)

    # ----------------------------------------------------------- logging
    def _log(self, msg):
        self.logger.info(msg)
        self.event_log.append({"t": round(time.time(), 3), "msg": msg})
        del self.event_log[:-MAX_EVENTS]

    # ------------------------------------------------- switch connection
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
      # Runs when a switch connects. Install a low-priority table-miss rule
        # and a higher-priority ARP rule so those packets are sent to Ryu.
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        to_ctrl = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, PRIO_MISS, parser.OFPMatch(), to_ctrl)
        self._add_flow(dp, PRIO_ARP,
                       parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP), to_ctrl)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.dps[dp.id] = dp
        else:
            self.dps.pop(dp.id, None)

    # ---------------------------------------------------------- topology
    @set_ev_cls([event.EventSwitchEnter, event.EventSwitchLeave,
                 event.EventLinkAdd, event.EventLinkDelete])
    def _topology_event(self, ev):
      # Ryu raises these events when switches/links appear or disappear.
        # Schedule one delayed reroute instead of reacting repeatedly to the
        # two endpoint events generated by a single physical/logical link change.
        self._log("topology event: %s" % ev.__class__.__name__)
        if not self._pending:                 # coalesce bursts of events
            self._pending = True
            hub.spawn(self._deferred_reroute)

    def _deferred_reroute(self):
        hub.sleep(DEBOUNCE_S)
        self._pending = False
        try:
            self._refresh_topology()
            self._reroute_all("topology change")
        except Exception as e:                # never let the app die
            self.logger.exception("reroute failed: %s", e)

    def _refresh_topology(self):
      # Ask Ryu's topology service for the current links and switch ports,
        # then rebuild PathEngine's graph using the latest network view.
        links = get_link(self, None)
        self.engine.set_links([(l.src.dpid, l.src.port_no, l.dst.dpid, l.dst.port_no)
                               for l in links])
        ports = {}
        for sw in get_switch(self, None):
            ports[sw.dp.id] = [p.port_no for p in sw.ports
                               if p.port_no <= ofproto_v1_3.OFPP_MAX]
        self.switch_ports = ports

    def _edge_ports(self, dpid):
     # Edge ports connect to end hosts; link ports connect to other switches.
        # Restricting ARP flooding to edge ports prevents broadcast loops.
        return [p for p in self.switch_ports.get(dpid, [])
                if not self.engine.is_link_port(dpid, p)]

    # ------------------------------------------------------- policy file
    def _policy_loop(self):
        while True:
            hub.sleep(0.3)
            self._poll_policy_once()

    def _poll_policy_once(self):
     # The dashboard writes selected paths to a JSON policy file. Check its
        # modification time; only parse and apply it when the file has changed.
        """Apply the policy file if it changed since last time. True if applied."""
        try:
            st = os.stat(POLICY_FILE)
            if st.st_mtime_ns == getattr(self, "_policy_mtime", None):
                return False
            with open(POLICY_FILE) as f:
                data = json.load(f)
            self._policy_mtime = st.st_mtime_ns
            self.pins = [[int(x) for x in p] for p in data.get("pins", [])]
            self.policy_seq = int(data.get("seq", 0))
            self._log("policy #%d applied: pins=%s" % (self.policy_seq, self.pins))
            self._refresh_topology()
            self._reroute_all("policy")
            return True
        except (OSError, ValueError, TypeError):
            return False                      # no file yet / half-written file
        except Exception as e:
            self.logger.exception("policy poll error: %s", e)
            return False

    # ------------------------------------------------------ flow helpers
    def _add_flow(self, dp, priority, match, actions):
     # Send an OpenFlow FLOW_MOD that says: when a packet matches this rule,
        # perform the supplied action (normally output it through a port).
        parser, ofp = dp.ofproto_parser, dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority,
                                      match=match, instructions=inst))

    def _del_flow(self, dp, priority, match):
      # Remove an exact matching rule. This is important when a destination
        # becomes unreachable, otherwise an old/stale route could remain active.
        parser, ofp = dp.ofproto_parser, dp.ofproto
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE_STRICT,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      priority=priority, match=match))

    def _packet_out(self, dp, ports, data):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        actions = [parser.OFPActionOutput(p) for p in ports]
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=ofp.OFPP_CONTROLLER,
                                        actions=actions, data=data))

    # ------------------------------------------------- host learning/flows
    def _learn(self, ip, mac, dpid, port):
      # Learn where a host is attached using its source IP/MAC and switch port.
        # Ignore ARP probes (0.0.0.0) and packets arriving from switch links.
        if ip == "0.0.0.0" or self.engine.is_link_port(dpid, port):
            return                                   # ARP probe, or seen on a switch-switch port
        cur = self.hosts.get(mac)
        if cur and cur["ip"] == ip and cur["dpid"] == dpid and cur["port"] == port:
            return
        self.hosts[mac] = {"ip": ip, "mac": mac, "dpid": dpid, "port": port}
        self.ip_to_mac[ip] = mac
        self._log("learned host %s (%s) on %s port %d" % (ip, mac, sname(dpid), port))
        self._install_host(mac)
        self._export_state()

    def _install_host(self, mac):
      # Calculate a route to this host and install destination-MAC rules on
        # every switch along the route. Delete rules on switches no longer used.
        """(Re)program every switch with the route towards this host."""
        h = self.hosts[mac]
        out = self.engine.routes_to(h["dpid"], h["port"], self.pins)
        self.routes[mac] = out
        for dpid, port in out.items():
            dp = self.dps.get(dpid)
            if dp is None:
                continue
            parser = dp.ofproto_parser
            self._add_flow(dp, PRIO_HOST, parser.OFPMatch(eth_dst=mac),
                           [parser.OFPActionOutput(port)])
        for dpid in self.installed.get(mac, set()) - set(out):   # stale / unreachable
            dp = self.dps.get(dpid)
            if dp is not None:
                self._del_flow(dp, PRIO_HOST, dp.ofproto_parser.OFPMatch(eth_dst=mac))
        self.installed[mac] = set(out)

    def _reroute_all(self, reason):
      # Recalculate and reinstall routes for every learned host after a link
        # change or dashboard policy update, then export the new controller state.
        t0 = time.time()
        for mac in list(self.hosts):
            self._install_host(mac)
        self._log("flows reinstalled (%s) in %.1f ms" % (reason, (time.time() - t0) * 1000))
        self._export_state()

    # ----------------------------------------------------------- packets
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
     # Handle packets that a switch sends to the controller. Ignore LLDP
        # (used internally by topology discovery); send ARP and IPv4 to handlers.
        try:
            msg = ev.msg
            dp, in_port = msg.datapath, msg.match["in_port"]
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            a = pkt.get_protocol(arp.arp)
            if a is not None:
                return self._handle_arp(dp, in_port, a, msg.data)
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip is not None:
                return self._handle_ip(dp, in_port, eth, ip, msg.data)
        except Exception as e:
            self.logger.exception("packet-in error: %s", e)

    def _handle_arp(self, dp, in_port, a, data):
      # Learn the sender. If the target is known, answer with proxy ARP;
        # otherwise flood only to host-facing ports. ARP replies are sent to
        # the port where the requesting host was learned.
        self._learn(a.src_ip, a.src_mac, dp.id, in_port)
        if a.opcode == arp.ARP_REQUEST:
            target = self.hosts.get(self.ip_to_mac.get(a.dst_ip))
            if target is not None:                       # proxy ARP reply
                p = packet.Packet()
                p.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                                 dst=a.src_mac, src=target["mac"]))
                p.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=target["mac"],
                                       src_ip=target["ip"], dst_mac=a.src_mac,
                                       dst_ip=a.src_ip))
                p.serialize()
                self._packet_out(dp, [in_port], p.data)
            else:                                        # flood edge ports only
                for dpid, d in self.dps.items():
                    ports = [p for p in self._edge_ports(dpid)
                             if not (dpid == dp.id and p == in_port)]
                    if ports:
                        self._packet_out(d, ports, data)
        elif a.opcode == arp.ARP_REPLY:
            dst = self.hosts.get(a.dst_mac)
            if dst is not None and dst["dpid"] in self.dps:
                self._packet_out(self.dps[dst["dpid"]], [dst["port"]], data)

    def _handle_ip(self, dp, in_port, eth, ip, data):
      # Learn the source host, look up the destination MAC, and forward the
        # packet through the route already calculated for that destination.
        # Unknown destinations are dropped because no safe output port is known.
        self._learn(ip.src, eth.src, dp.id, in_port)
        dst = self.hosts.get(eth.dst)
        if dst is None:
            return                                       # unknown destination: drop
        port = self.routes.get(dst["mac"], {}).get(dp.id)
        if port is not None:
            self._packet_out(dp, [port], data)

    # ------------------------------------------------------- state export
    def _export_state(self):
      # Publish the controller's real view of the network as JSON: hosts,
        # links, chosen paths, active pins and timestamped events. The dashboard
        # reads this file so its topology/route display reflects installed logic.
        try:
            paths = {}
            for sm, s in self.hosts.items():
                for dm, d in self.hosts.items():
                    if sm == dm:
                        continue
                    tr = self.engine.trace(s["dpid"], d["dpid"], self.routes.get(dm, {}))
                    paths["%s->%s" % (s["ip"], d["ip"])] = \
                        [sname(x) for x in tr] if tr else None
            links = sorted({tuple(sorted((a, b)))
                            for a, nb in self.engine.adj.items() for b in nb})
            _atomic_write(STATE_FILE, {
                "updated": round(time.time(), 3),
                "policy_seq": self.policy_seq,
                "pins": [[sname(x) for x in p] for p in self.pins],
                "switches": sorted(sname(d) for d in self.dps),
                "links": [[sname(a), sname(b)] for a, b in links],
                "hosts": [{"ip": h["ip"], "mac": h["mac"], "switch": sname(h["dpid"]),
                           "port": h["port"]} for h in self.hosts.values()],
                "paths": paths,
                "events": self.event_log,
            })
        except Exception as e:
            self.logger.warning("could not write state file: %s", e)
