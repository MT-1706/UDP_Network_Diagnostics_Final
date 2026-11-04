#!/usr/bin/env python3
"""
Web dashboard backend for the UDP Network Diagnostic & Path Analysis Tool.

Uses only the Python standard library.  It:
  * runs your existing udp_probe.py (UDP probes -> RTT, loss, jitter)
  * reads the SDN topology from the Ryu REST API (same one analyzer.py uses)
  * correlates the probe with the network path (BFS, same as analyzer.py)
  * enumerates ALTERNATIVE paths and compares them
  * serves the front end in ./static

Run (root namespace, so it can reach Ryu on 127.0.0.1:8080):
    sudo python3 dashboard_server.py
Then open  http://127.0.0.1:5000
"""
import argparse, ipaddress, json, os, shutil, subprocess, sys, threading, time   # argparse=command-line options, ipaddress=validate IPs, json=read/write JSON, os=paths, shutil=find programs, subprocess=run commands, sys=interpreter/stderr, threading=Lock, time=clock
import urllib.request   # lets us make HTTP requests (to Ryu's REST API)
import sdn_control      # our helper module: controller state file, policy pins, tc impairment
from collections import deque   # double-ended queue, used as the queue in BFS
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer   # ready-made web server classes (one thread per request)

HERE = os.path.dirname(os.path.abspath(__file__))    # folder this file lives in
STATIC = os.path.join(HERE, "static")     # folder holding the web page files (HTML/CSS/JS)
PROBE_SCRIPT = os.path.join(HERE, "udp_probe.py")    # full path of the UDP probe program we run

# Topology identical to topo.py, used only if Ryu is not reachable.
DEMO = {    # built-in copy of the network, a fallback so the page can still draw something
    "switches": ["0000000000000001", "0000000000000002", "0000000000000003"],   # switch IDs (dpids) in Ryu's 16-digit format
    "links": [("0000000000000001", "0000000000000002"),
              ("0000000000000002", "0000000000000003"),
              ("0000000000000001", "0000000000000003")], 
    "hosts": [{"ip": "10.0.0.1", "dpid": "0000000000000001"}, 
              {"ip": "10.0.0.3", "dpid": "0000000000000002"},
              {"ip": "10.0.0.2", "dpid": "0000000000000003"}],
}

CFG = {}        # gets the settings from cli like src IP, mn host
HISTORY = []    # last 50 diagnosis summaries recorded here 
LOCK = threading.Lock()     # Locks to maintain consistency of shared memory
KNOWN_LINKS = {}   # every link ever seen recorded here. Format: (dpidA, dpidB) -> {dpid: interface name}
KNOWN_HOSTS = {}   # every host ever seen ip -> dpid

# convert Ryu switch dpid into shorter name
def short(d):   
    return "s" + str(int(d, 16))

# the opposite of short()
def full(name):                                      
    """'s3' -> '0000000000000003' (Ryu's dpid format)"""
    return "%016x" % int(name.lstrip("s"))           

# ----------------------------------- TOPOLOGY ----------------------------------- 
# ask Ryu's REST API for 1 thing
def ryu_get(path):                                   
    with urllib.request.urlopen(f"{CFG['ryu']}/{path}", timeout=2) as r:   # open Ryu's address + path, give up after 2 seconds
        return json.load(r)     # conv Ryu's JSON reply to Py lists/dicts

# interface name of 1 end of a link in format like "s1-eth2"
def _ifname(end, dpid):                              
    return end.get("name") or f"{short(dpid)}-eth{int(str(end.get('port_no', 1)))}"   # use Ryu's name if it gave one, else build it from the port number

# build curr graph topology as decided in topo.py
def load_topology():                               
    """Current topology + links that were seen before but are gone now."""
    # if anything fails --> Ryu down so use demo copy
    try:                                            
        switches = [s["dpid"] for s in ryu_get("switches")]   # IDs of all known Ryu switches
        if not switches:    # empty list so ntg seen by Ryu yet
            raise ValueError("Ryu returned no switches")    # treat as an error so we use the demo
        now = set()     # curr existing links
        with LOCK:      # lock allows only 1 thread to modify the shared memory at a time to avoid data inconsistency 
            for l in ryu_get("links"):      # Ryu lists each physical link twice as the same link as pkt traverses the same link 2 times
                a, b = l["src"]["dpid"], l["dst"]["dpid"]     # the two switches this entry connects
                k = tuple(sorted((a, b)))       # sorted pair, both directions have same key
                now.add(k)      # this link is up now
                KNOWN_LINKS[k] = {a: _ifname(l["src"], a), b: _ifname(l["dst"], b)}   # remember link w/ interface name at each end
            for h in ryu_get("hosts"):      # every host Ryu has learned abt that link
                for ip in h.get("ipv4", []):    # go thru host IPs
                    KNOWN_HOSTS[ip] = h["port"]["dpid"]    # remember which switch host is on
            known = set(KNOWN_LINKS)    # set of every link ever seen (up or down)
            hosts = [{"ip": ip, "dpid": d} for ip, d in KNOWN_HOSTS.items()]   # list of dicts of hosts and their info
        return {"source": "ryu", "switches": sorted(set(switches) | 
                {d for k in known for d in k}),     # data came from Ryu plus any switch that appears in a remembered link
                "links": sorted(now), "all_links": sorted(known),     # links up now
                "down": sorted(known - now), "hosts": hosts, "note": ""}   # DOWN = seen before but missing rn
    except Exception as e:      # Ryu unreachable / ret.d sometsmtghing odd
        d = DEMO    # use built-in topology
        links = sorted(tuple(sorted(l)) for l in d["links"])   # sorted-pair same as above
        return {"source": "demo", "switches": d["switches"], "links": links,   # mark data as demo
                "all_links": links, "down": [], "hosts": d["hosts"],    # demo has no failed links
                "note": f"Ryu controller not reachable ({e}). Showing the "    # msg shown on page w/ reason
                        f"built-in topology from topo.py."}

 # format links for front end
def link_list(t):                                   
    return [[short(a), short(b), "down" if (a, b) in t["down"] else "up"] 
            for a, b in t["all_links"]]     # for every link ever seen

# turn a link off(Fail button) / on(Restore button) for front end
def set_link(name_a, name_b, action):
    """Bring a link down/up by toggling both switch-side interfaces."""
    if action not in ("down", "up"):    # the only 2 words allowed
        raise ValueError("action must be 'down' or 'up'")
    load_topology()     # refresh KNOWN_LINKS to know interface names
    with LOCK:      # read dict in shared memory w/out any inconsistency in its data
        key = next((k for k in KNOWN_LINKS      # find link whose 2 switch names match name_a/name_b
                    if {short(k[0]), short(k[1])} == {name_a, name_b}), None)   # in sets s1-s2 = s2-s1 & None if not found
        ifs = list(KNOWN_LINKS[key].values()) if key else []   # 2 interface names, e.g. ["s1-eth2","s2-eth2"]
    if not key:     # no such link
        raise ValueError(f"Unknown link {name_a}-{name_b} "
                         "(only works with the live Ryu topology)")
    done = []       # interfaces we managed to change
    for i in ifs:   # both ends of the link
        try:
            r = subprocess.run(["ip", "link", "set", i, action],    # cli to switch interface off/on
                               capture_output=True, text=True)      # capture o/p instead of printing it
        except OSError as e:    # if ip prog. is missing
            raise RuntimeError(f"cannot run 'ip' command: {e}")
        if r.returncode == 0:   # 0 means command succeeded
            done.append(i)
    if not done:    # ntg worked (probs with root)
        raise RuntimeError(f"Could not set {ifs} {action} - run the dashboard "
                           f"with sudo from the machine running Mininet.")
    return {"link": [name_a, name_b], "action": action, "interfaces": done}   # report what was done

# creates adjcy list: switch -> set of neighbouring switches
def build_graph(topo):                               
    g = {s: set() for s in topo["switches"]}    # every switch starts with no neighbours
    for a, b in topo["links"]:      # for every link
        g[a].add(b)     # a can reach b
        g[b].add(a)     # b can reach a, as links work both ways
    return g
    # causes redundancy in list therefore we use set

# which switch is this host plugged into
def host_switch(topo, ip):                           
    for h in topo["hosts"]:     # look through the known hosts
        if h["ip"] == ip:    # find it
            return h["dpid"]
    return None     # host not found/unknown

# every loop-free path from switch a to switch b using DFS
def all_paths(g, a, b, limit=20):                    
    """All simple switch-level paths a->b, shortest first (DFS)."""
    out = []    # completed paths stored here

    def dfs(node, path):    # iterate for all possible routes
        if len(out) >= limit * 5:       # safety cap so a big n.w. doesn't run forever
            return
        if node == b:   # reached dest
            out.append(list(path))      # save copy of curr path
            return
        for n in sorted(g[node]):   # try each neighbour
            if n not in path:   # never revisit a switch, no loop
                path.append(n)  # move fwd
                dfs(n, path)    # explore from there
                path.pop()   # backtrack & try oth neighbours
    dfs(a, [a])     # start at a, with a as path so far
    out.sort(key=len)   # shortest paths first
    return out[:limit]      # at most lim paths

# bfs to find shortest path/fewest hops from a to b
def bfs(g, a, b):   
    q, seen = deque([[a]]), {a}     # q holds partial paths
    while q:    # until ntg left to explore
        p = q.popleft()   # take oldest partial path (this makes it level-by-level)
        if p[-1] == b:   # last switch is target
            return p    # fst one found is shortest
        for n in g[p[-1]]:  # each neighbour of path's last switch
            if n not in seen:   # skip switches already reached
                seen.add(n)   # mark as visited
                q.append(p + [n])   # q path extended by this neighbour
    return None     # q emptied w/out reaching b, so no route

# ------------------------------------ PROBE ------------------------------------
# find PID of Mn host 
def find_mininet_pid(host):                          
    try:
        out = subprocess.run(["pgrep", "-f", f"mininet:{host}$"],   # search running processes whose cli ends w/ "mininet:h1"
                             capture_output=True, text=True, timeout=3).stdout   # keep only printed text
        pids = out.split()      # list of matching PIDs
        return pids[0] if pids else None    # fst, or None if none
    except Exception:   # pgrep missing, timed out, etc.
        return None

# make cmd run IN mn host
def in_host(cmd):                                    
    """Prefix `cmd` so it runs inside the Mininet host if possible; returns (cmd, where)."""
    pid = find_mininet_pid(CFG["mn_host"]) if shutil.which("mnexec") else None   # need `mnexec` tool & host's PID
    if pid and not CFG["local_probe"]:      # both found & the user didn't ask for local probing
        return ["mnexec", "-a", pid] + cmd, f"mininet:{CFG['mn_host']}"   # "mnexec -a PID cmd" runs cmd in that host's network namespace
    return cmd, "local"     # else run it on this machine as is

# run udp_probe.py and return its results
def run_probe(dst, count, interval=0.1, timeout=1.0):   
    """Run udp_probe.py (from inside the Mininet host if possible)."""
    cmd, where = in_host([sys.executable, PROBE_SCRIPT, dst, str(count),    # if cmd matches given format stored here
                          str(interval), str(timeout)])
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE,   # run it cmd -> capture o/p from this folder
                       timeout=count * (interval + timeout) + 15)   # kill after worst case (every probe times out) + 15 s
    if r.returncode != 0:   # if probe prog failed
        raise RuntimeError(r.stderr.strip() or "udp_probe.py failed")   # raise its error message
    res = json.loads(r.stdout)      # probe printed JSON then it conved to a py dict
    res["probe_origin"] = where     # note where it ran ("mininet:h1" or "local")
    return res

# ------------------------------------ ANALYSIS ------------------------------------ 
# calcs expected RTT of path from config.d link delays
def est_rtt(path):                                   
    """Expected RTT (ms) of a switch path from topo.py's configured link delays
    (2 directions x sum of link delays) plus any injected delay; None if unknown."""
    total = 0.0     # sum of 1-way delays
    for a, b in zip(path, path[1:]):    # each pair of neighbouring switches = one link on path
        na, nb = short(a), short(b)     # get their short names
        d = sdn_control.base_delay(na, nb)      # link's delay from topo.py's file (None if unknown)
        if d is None:   # if no d return None, no estimate
            return None
        extra = sdn_control.IMPAIRED.get("%s-%s" % tuple(sorted((na, nb))), {}).get("delay", 0)   # extra delay put on this link (0 if none)
        total += d + extra      # add link's delay
    return round(2 * total, 2)  # x2 as pkt goes to dest & comes back

# the main function: probe + topology -> verdict
def analyse(dst, count):                             
    probe = run_probe(dst, count)   # send UDP probes & get imp params like: RTT/loss/jitter
    topo = load_topology()  # ask Ryu what n.w. looks like rn
    g_now = build_graph(topo)   # links that are up rn
    g_all = build_graph({"switches": topo["switches"], "links": topo["all_links"]})   # every link ever seen
    down = set(topo["down"])    # failed links: seen b4 but missing now
    down_names = [[short(a), short(b)] for a, b in sorted(down)]   # list of switch pairs
    src_sw = host_switch(topo, CFG["src_ip"])   # switch src host is on
    dst_sw = host_switch(topo, dst)     # switch dest host is on

    paths, primary, original, warn = [], None, None, []   # all paths / active / normal / warnings  (empty @ start)
    path_source = "inferred (BFS)"      # where active path comes from; changed below if ctrl.r tells us
    if src_sw is None or dst_sw is None:    # 1 of the hosts is unknown to Ryu
        missing = CFG["src_ip"] if src_sw is None else dst   # which host is missing
        warn.append(f"Host {missing} not found in topology - run pingall "   # warning for frontend
                    f"in Mininet so the controller learns the hosts.")
    else:   # both hosts known, so paths can be worked out
        primary = bfs(g_now, src_sw, dst_sw)    # path avail now
        ctrl = sdn_control.read_state()   # dynamic ctrl.r's published state (None if not running)
        key = f"{CFG['src_ip']}->{dst}"     # lookup key, e.g. "10.0.0.1->10.0.0.2"
        if ctrl and key in ctrl.get("paths", {}):   # dynamic app: path really prog.d
            cp = ctrl["paths"][key]     # e.g. ["s1","s3"], or None if ctrl.r found no route
            primary = [full(x) for x in cp] if cp else None   # use ctrl.r's path (conv.d to dpids)
            path_source = "controller"      # remember use of real one
        original = bfs(g_all, src_sw, dst_sw)   # path when ntg is down
        paths = all_paths(g_all, src_sw, dst_sw)    # every possible path, for comparison table

    loss, avg = probe["loss_pct"], probe["rtt_avg_ms"]   # 2 probe no.s used repeatedly
    route = " -> ".join(short(d) for d in primary) if primary else "unknown path"   # readable route format: "s1 -> s3"
    rerouted = bool(primary and original and primary != original)   # True if traffic uses diff path than normal
    cause = ""      # explanation text, filled depending on cases below
    # CASE 1: both hosts known but no route exists
    if src_sw and dst_sw and primary is None:        
        status = "failed"                            # overall health label
        diag = "Path FAILED - no route in the topology"   # headline shown on frontend
        # next statement picks 1/2 msgs: if failed links are known, name them; else use generic text.
        cause = ("Topology is disconnected: failed link(s) " +
                 ", ".join("-".join(x) for x in down_names) +    # ["s1","s2"] -> "s1-s2", joined by commas
                 " left no route between the hosts.") if down_names else \
                "No route between the hosts in the controller's topology."
    # CASE 2: route exists but every probe was lost
    elif loss == 100:                                
        status = "failed"
        diag = "Path FAILED - no replies received"
        cause = ("Controller still sees a route, but nothing came back: the "   # prob is server / fwding rules
                 "destination UDP echo server may be down, or the switches "
                 "are not forwarding (flows missing / stale after a failure).")
        # if probe reported socket error add fst 1 to explanation
        if probe.get("errors"):     
            cause += " Socket error: " + probe["errors"][0]
    # CASE 3: some packets lost, not all
    elif loss > 0:                                   
        status = "degraded"
        diag = "DEGRADED path - packet loss on " + route   # include route in headline
        cause = "Partial loss on the active path: congestion, a lossy link, or a link that is flapping."
    # CASE 4: no loss at all
    else:                                            
        status = "healthy"
        diag = "Path healthy"
    if rerouted and status != "failed":     # traffic uses a non-default path and it still works
        if down_names:      # a link really is down
            diag += " (rerouted around failed link)"
            cause = ("Original path " + " -> ".join(short(d) for d in original) +   # the normal path
                     " is down; traffic now uses " + route + ".")   # curr path
        # nothing down: path was chosen (pinned)
        else:                                      
            diag += " (using a non-default path)"
            cause = ("Traffic uses " + route + " instead of the default " +
                     " -> ".join(short(d) for d in original) +
                     " - a pinned path chosen from the dashboard.")

    # Per-link RTT estimate (assumes equal delay on every inter-switch link) - only
    # used when topo.py's real per-link delays are not available.
    per_link = None     # stays None if we can't estimate
    if primary and len(primary) > 1 and probe["rtt_min_ms"] is not None:   # need path w/ @ least 1 link & measured min RTT
        per_link = probe["rtt_min_ms"] / (len(primary) - 1)   # min RTT divided by the number of links (switches - 1)

    plist = []      # 1 dict/path for comparison table
    for p in paths:     # go thru every possible path
        bad = [[short(a), short(b)] for a, b in zip(p, p[1:])   # zip(p, p[1:]) pairs each switch w/ next = links on this path
               if tuple(sorted((a, b))) in down]     # keep only links that are down
        is_primary = (p == primary)     # is this path curr.ly in use?
        if bad:     # it contains a down link
            st = "failed"
        elif is_primary:     # active path takes overall status
            st = status
        else:       # all links up, just not in use
            st = "available"
        plist.append({     # add this path's row
            "names": [short(d) for d in p], "hops": len(p), "primary": is_primary,   # readable names, # of switches, is it active
            "status": st, "down_links": bad,     # its status & which of its links are down
            "measured_rtt_ms": avg if is_primary else None,   # only active path was truly measured by this probe
            "est_rtt_ms": est_rtt(p) if est_rtt(p) is not None else   # estimate from topo.py's configured delays
                          (round(per_link * (len(p) - 1), 2) if per_link else None),   # if no info: per-link RTT x # of links
        })
    plist.sort(key=lambda x: (x["status"] == "failed", x["hops"]))   # working paths fst (False sorts b4 True as lexicographical order)
                                                                     #then fewest hops

    suspects = []   # links to be investigated
    if status != "healthy":     # only needed when smtg is wrong
        if down_names:      # known failed links are suspects
            suspects = down_names
        elif primary:       # otherwise every link on active path
            suspects = [[short(a), short(b)] for a, b in zip(primary, primary[1:])]
    recommend = None    # suggested fix shown as "Suggested reroute"
    if status != "healthy":     # only needed when smtg is wrong
        alt = next((p for p in plist if p["status"] == "available"), None)   # fst working alt = shortest as list is sorted
        if alt:     # a working alt exists
            recommend = " -> ".join(alt["names"])    # recommend the alt
        elif down_names:    # no alts but we know which links are down
            recommend = "No working alternative - restore " + \
                        ", ".join("-".join(x) for x in down_names)   # joining strings in format: "s1-s2, s2-s3"
        else:   # no alt & ntg known to be down
            recommend = "No alternative path exists (redundant link needed)."

    result = {      # single dict sent back to frontend as JSON
        "time": time.strftime("%H:%M:%S"),      # when this diagnosis ran
        "src": CFG["src_ip"], "dst": dst, "probe": probe,   # src IP, dest IP, raw probe no.s
        "status": status, "diagnosis": diag, "cause": cause, "warnings": warn,   # verdict w/ explanation
        "rerouted": rerouted, "down_links": down_names,    # reroute flag & failed links
        "topology": {     # data frontend needs to draw the map
            "source": topo["source"], "note": topo["note"],   # ("ryu" or "demo") + any aditional note->optional
            "switches": [short(s) for s in topo["switches"]],   # switch names
            "links": link_list(topo),   # displaying list of switches w/in a list as in: [["s1","s2","up"], ...]
            "hosts": [{"ip": h["ip"], "switch": short(h["dpid"])}   # each host & switch it is on
                      for h in topo["hosts"]],
        },
        "primary": [short(d) for d in primary] if primary else None,   # active path as names (None if no path)
        "path_source": path_source,     # "ctrl.r" / "inferred (BFS)"
        "paths": plist, "suspect_links": suspects, "recommend": recommend,   # table rows, suspect links, suggested fix
    }
    # allow only 1 web rqst @ a time to change HISTORY (which is the shared memory in this case) to avoid data inconsistency
    with LOCK:   
        HISTORY.append({"time": result["time"], "dst": dst, "status": status,   # add short summary of this run
                        "loss_pct": loss, "rtt_avg_ms": avg,    # loss & avg RTT
                        "jitter_ms": probe["jitter_ms"],    # jitter
                        "path": " -> ".join(result["primary"] or []) or "n/a"})  # path as text / "n/a" if there was none
        del HISTORY[:-50]   # keep only last 50 entries
    return result   # hand res to frontend handler



# -------------------------------- DYNAMIC SDN OPERATIONS --------------------------------
# find src & dest switches / raise apt error
def _hosts_for(dst):                                
    topo = load_topology()  # gets the curr topology as described in topo.py
    src_sw, dst_sw = host_switch(topo, CFG["src_ip"]), host_switch(topo, dst)   # gets switches of both hosts
    if src_sw is None or dst_sw is None:    # host which hasn't been learned yet
        raise ValueError("source or destination host not known to the controller - run pingall")
    return topo, src_sw, dst_sw     # give back evth caller needs


 # measure every path one by one
def measure_paths(dst, count=15):                   
    """Pin every loop-free path in turn, probe it, and compare MEASURED values.
    Leaves the controller with no pins (default routing) afterwards."""
    if sdn_control.read_state() is None:    # if no state file => dynamic ctrl.r app isn't running
        raise RuntimeError("dynamic controller app not running (start dynamic_path_app.py)")
    topo, a, b = _hosts_for(dst)    # topology & 2 switches
    paths = all_paths(build_graph(topo), a, b)      # every working loop-free path
    if not paths:   # if no paths exist
        raise ValueError("no working path between the hosts")
    rows = []   # 1 result row/path
    try:
        for p in paths:     # iterate thru each path
            names = [short(x) for x in p]       # calling func to shorten names
            pol = sdn_control.set_policy([names])    # tell ctrl.r t0 use exactly this path
            actual = pol["paths"].get(f"{CFG['src_ip']}->{dst}")   # path the ctrl.r says it prog.d
            row = {"names": names, "hops": len(p), "est_rtt_ms": est_rtt(p),   # start row: path, switch count, expected RTT
                   "pinned": bool(pol["applied"] and actual == names)}      # True only if confirmed & matches what we asked
            # path really in use
            if row["pinned"]:       
                pr = run_probe(dst, count, 0.05, 0.5)   # measure it (faster settings: 50 ms gap, 0.5 s timeout)
                row.update(measured_rtt_ms=pr["rtt_avg_ms"], min_rtt_ms=pr["rtt_min_ms"],   # add measured no.s
                           jitter_ms=pr["jitter_ms"], loss_pct=pr["loss_pct"])
            # ctrl.r didn't apply the path
            else:
                row["error"] = "controller did not apply this path (got %s)" % actual   # don't measure show error
            rows.append(row)    # keep record of the row
    finally:    # runs even if stmg above failed
        sdn_control.set_policy([])     # always remove pin so normal routing ret.s
    ok = [r for r in rows if r.get("measured_rtt_ms") is not None]   # rows that were actually measured
    # best = least loss, then lowest RTT (None if ntg measured)
    best = min(ok, key=lambda r: (r["loss_pct"], r["measured_rtt_ms"]), default=None)   
    hop_choice = min(rows, key=lambda r: r["hops"]) if rows else None   # what normally fewest hops would choose
    # mark winner for frontend
    if best:                                         
        best["best"] = True
    return {"time": time.strftime("%H:%M:%S"), "src": CFG["src_ip"], "dst": dst,   # ans for frontend
            "paths": rows, "best": best["names"] if best else None,     # all rows & best path
            "fewest_hops": hop_choice["names"] if hop_choice else None,     # least-hop path
            "hop_count_choice_is_best": bool(best and hop_choice and best["names"] == hop_choice["names"])}   # do they agree?


# "apply" pins one path, "clear" removes pins
def apply_policy(action, path=None):    
    if sdn_control.read_state() is None:    # ctrl.r app not running
        raise RuntimeError("dynamic controller app not running (start dynamic_path_app.py)")
    if action == "clear":       # remove all pins
        return sdn_control.set_policy([])
    if action == "apply" and isinstance(path, list) and len(path) >= 2:   # valid path needs @ least 2 switches
        return sdn_control.set_policy([[str(x) for x in path]])     # pin it (names conv.d to text)
    raise ValueError("action must be 'clear' or 'apply' (with a path like ['s1','s2','s3'])")   # anything else is invalid


# break a link during traffic and measure the effect
def failover_test(dst, link, duration=10.0, fail_at=3.0, restore_at=7.0, interval=0.02):  
    """Stream UDP probes, fail a link mid-run, restore it, and report the outage."""
    if not (0 < fail_at < restore_at < duration):    # timings must be in sensible order
        raise ValueError("need 0 < fail_at < restore_at < duration")
    a, b = str(link[0]), str(link[1])       # 2 switch names of given link
    before = sdn_control.read_state()       # ctrl.r state b4 test (not used further)
    # cmd for fixed-rate stream probe w/ its dest, duration, gap & timeout
    cmd, where = in_host([sys.executable, os.path.join(HERE, "udp_stream_probe.py"),  
                          dst, str(duration), str(interval), "0.5"])                  
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=HERE)   # start it in bg (Popen doesn't w*)
    t_start, t_fail, t_restore, err = time.time(), None, None, None   # timestamps & error holder (t_start/t_restore aren't used further)
    try:
        time.sleep(fail_at)     # let traffic flow normally first
        t_fail = time.time()    # remember moment user breaks link
        set_link(a, b, "down")      # break link
        time.sleep(max(0, restore_at - fail_at))     # leave link broken until restored
        t_restore = time.time()     # remember when user restore it
    except Exception as e:    # anything went wrong above
        err = str(e)    # keep msg to report later
    # always runs
    finally:    
        try:
            set_link(a, b, "up")    # always restore
        except Exception as e:   # restoring failed
            err = err or str(e)     # keep fst error if there already is one
    out, errout = proc.communicate(timeout=duration * 2 + 20)   # wait for stream probe to finish & collect its o/p
    if proc.returncode != 0:    # probe prog. failed
        raise RuntimeError(errout.strip() or "udp_stream_probe.py failed")
    res = json.loads(out)   # JSON o/p as a dict
    if err:     # smtg went wrong during test
        res["warning"] = err    # pass msg to frontend
    st = sdn_control.read_state()   # ctrl.r state now (contains timestamped event log)
    # The next statement computes reaction times only if we have a state file and a failure time; otherwise (None, None).
    detect_ms, reroute_ms = sdn_control.reaction_times((st or {}).get("events"), t_fail) \
        if (st and t_fail) else (None, None)
    res.update(link=[a, b], probe_origin=where, fail_at_s=fail_at, restore_at_s=restore_at,   # add test details to result
               controller_detect_ms=detect_ms, controller_reroute_ms=reroute_ms,    # how fast the  ctrl.r noticed / reprog.d
               controller_available=bool(st),   # was dynamic  ctrl.r running?
               path_after=(st or {}).get("paths", {}).get(f"{CFG['src_ip']}->{dst}"))   # path in use after failure
    return res



# ------------------------------------------- FRONTEND -------------------------------------------
class Handler(SimpleHTTPRequestHandler):             # our web server: serves the page files and answers /api/... requests
    def __init__(self, *a, **kw):                    # runs for every request
        super().__init__(*a, directory=STATIC, **kw) # serve files from the static folder

    def log_message(self, fmt, *args):               # called to log each request
        sys.stderr.write("[web] " + fmt % args + "\n")   # print it with a [web] prefix

    def send_json(self, obj, code=200):              # reply with JSON
        body = json.dumps(obj).encode()              # Python data -> JSON text -> bytes
        self.send_response(code)                     # HTTP status (200 = OK)
        self.send_header("Content-Type", "application/json")   # tell the browser it is JSON
        self.send_header("Content-Length", str(len(body)))     # size of the body
        self.send_header("Cache-Control", "no-store")          # never cache: data changes constantly
        self.end_headers()                           # finish the header section
        self.wfile.write(body)                       # send the body

    def do_GET(self):                                # handles every GET request
        if self.path.startswith("/api/topology"):    # the page asks for the topology
            t = load_topology()
            return self.send_json({                  # answer with what the page needs to draw the map
                "source": t["source"], "note": t["note"],
                "src_ip": CFG["src_ip"],
                "switches": [short(s) for s in t["switches"]],
                "links": link_list(t),
                "hosts": [{"ip": h["ip"], "switch": short(h["dpid"])}
                          for h in t["hosts"]]})
        if self.path.startswith("/api/state"):       # the page asks for the dynamic controller's state
            st = sdn_control.read_state()            # None if the controller app is not running
            return self.send_json({"controller": st, "dynamic": st is not None,   # state, and whether the dynamic app is running
                                   "impaired": sdn_control.IMPAIRED,              # links with injected loss/delay
                                   "links_meta": sdn_control.read_meta()})        # link info from topo.py
        if self.path.startswith("/api/history"):     # the page asks for past diagnoses
            with LOCK:                               # read the shared list safely
                return self.send_json(HISTORY)
        return super().do_GET()                      # anything else is a normal file (index.html, app.js...)

    def _body(self):                                 # read the JSON sent by the page in a POST
        n = int(self.headers.get("Content-Length", 0))   # how many bytes the body has
        return json.loads(self.rfile.read(n) or b"{}")   # read them and parse JSON (empty body = empty dict)

    def dynamic_post(self, req):                     # handles the four new dynamic-SDN POST requests
        try:
            if self.path.startswith("/api/measure"):         # "Measure every path"
                dst = str(ipaddress.ip_address(req.get("dst", "")))   # check it is a real IP (raises ValueError if not)
                return self.send_json(measure_paths(dst, max(3, min(int(req.get("count", 15)), 100))))   # probes per path limited to 3..100
            if self.path.startswith("/api/policy"):          # apply or clear a pinned path
                return self.send_json(apply_policy(str(req.get("action")), req.get("path")))
            if self.path.startswith("/api/impair"):          # inject loss/delay on a link
                return self.send_json(sdn_control.impair(
                    str(req.get("a")), str(req.get("b")),                 # the link's two switches
                    float(req.get("loss", 0)), float(req.get("delay", 0))))   # loss % and extra delay ms
            dst = str(ipaddress.ip_address(req.get("dst", "")))           # otherwise it is /api/failover: validate the IP
            link = req.get("link") or []                                  # the link to break, e.g. ["s1","s3"]
            if len(link) != 2:                                            # must name exactly two switches
                raise ValueError("link must be [a, b], e.g. ['s1','s2']")
            return self.send_json(failover_test(
                dst, link, float(req.get("duration", 10)),                # test length in seconds
                float(req.get("fail_at", 3)), float(req.get("restore_at", 7))))   # when to break / restore
        except (ValueError, TypeError) as e:         # bad input from the user
            self.send_json({"error": str(e)}, 400)   # 400 = bad request
        except Exception as e:                       # anything else (tc missing, controller not running...)
            self.send_json({"error": str(e)}, 500)   # 500 = server error

    def do_POST(self):                               # handles every POST request
        try:
            req = self._body()                       # the JSON the page sent
        except Exception:                            # not valid JSON
            return self.send_json({"error": "Bad JSON"}, 400)
        if self.path.startswith("/api/link"):        # Fail link / Restore buttons
            try:
                return self.send_json(set_link(str(req.get("a")), str(req.get("b")),
                                               str(req.get("action"))))
            except ValueError as e:                  # unknown link or bad action
                return self.send_json({"error": str(e)}, 400)
            except Exception as e:                   # e.g. not running as root
                return self.send_json({"error": str(e)}, 500)
        if self.path.startswith("/api/reset"):       # "Reset remembered topology & history" button
            with LOCK:
                KNOWN_LINKS.clear(); KNOWN_HOSTS.clear(); HISTORY.clear()   # forget everything remembered
            return self.send_json({"ok": True})
        if self.path.startswith(("/api/measure", "/api/policy", "/api/impair", "/api/failover")):   # the four dynamic requests
            return self.dynamic_post(req)            # handled by the function above
        if not self.path.startswith("/api/diagnose"):   # not a known address
            return self.send_json({"error": "not found"}, 404)
        try:                                         # it is /api/diagnose: validate the input
            dst = str(ipaddress.ip_address(req.get("dst", "")))        # destination must be a valid IP
            count = max(1, min(int(req.get("count", 20)), 200))        # number of probes limited to 1..200
        except Exception:
            return self.send_json({"error": "Invalid destination IP or count"}, 400)
        try:
            self.send_json(analyse(dst, count))      # run the diagnosis and reply with the result
        except subprocess.TimeoutExpired:            # the probe took too long
            self.send_json({"error": "Probe timed out"}, 500)
        except Exception as e:                       # any other failure
            self.send_json({"error": str(e)}, 500)

def main():                                          # program start
    ap = argparse.ArgumentParser(description=__doc__,   # command-line option parser; shows the top docstring as help
                                 formatter_class=argparse.RawTextHelpFormatter)   # keep the docstring's line breaks
    ap.add_argument("--port", type=int, default=5000)          # web page port
    ap.add_argument("--bind", default="127.0.0.1")             # address to listen on (only this machine by default)
    ap.add_argument("--ryu", default="http://127.0.0.1:8080/v1.0/topology")   # where Ryu's REST API is
    ap.add_argument("--src-ip", default="10.0.0.1")            # IP of the host that sends probes (h1)
    ap.add_argument("--mn-host", default="h1",                 # which Mininet host runs the probe
                    help="Mininet host to send probes from (default h1)")
    ap.add_argument("--local-probe", action="store_true",      # flag: no value needed, just present or absent
                    help="send probes from this machine, not from a Mininet host")
    a = ap.parse_args()                              # read the command line
    CFG.update(ryu=a.ryu.rstrip("/"), src_ip=a.src_ip,          # store the settings in the global CFG
               mn_host=a.mn_host, local_probe=a.local_probe)    # (rstrip removes a trailing "/")
    print(f"Dashboard: http://{a.bind}:{a.port}   (Ryu API: {CFG['ryu']})")   # tell the user where to open the page
    ThreadingHTTPServer((a.bind, a.port), Handler).serve_forever()   # start the server and run until stopped, one thread per request

if __name__ == "__main__":                           # true only when this file is run directly (not imported)
    main()                                           # start the program

