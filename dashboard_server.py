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
import argparse, ipaddress, json, os, shutil, subprocess, sys, threading, time
import urllib.request
import sdn_control
from collections import deque
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
PROBE_SCRIPT = os.path.join(HERE, "udp_probe.py")

# Topology identical to topo.py, used only if Ryu is not reachable.
DEMO = {
    "switches": ["0000000000000001", "0000000000000002", "0000000000000003"],
    "links": [("0000000000000001", "0000000000000002"),
              ("0000000000000002", "0000000000000003"),
              ("0000000000000001", "0000000000000003")],
    "hosts": [{"ip": "10.0.0.1", "dpid": "0000000000000001"},
              {"ip": "10.0.0.3", "dpid": "0000000000000002"},
              {"ip": "10.0.0.2", "dpid": "0000000000000003"}],
}

CFG = {}
HISTORY = []
LOCK = threading.Lock()
KNOWN_LINKS = {}   # (dpidA, dpidB) -> {dpid: interface name}  (every link ever seen)
KNOWN_HOSTS = {}   # ip -> dpid  (every host ever seen)


def short(d):
    return "s" + str(int(d, 16))


def full(name):
    """'s3' -> '0000000000000003' (Ryu's dpid format)"""
    return "%016x" % int(name.lstrip("s"))


# ---------------------------------------------------------------- topology
def ryu_get(path):
    with urllib.request.urlopen(f"{CFG['ryu']}/{path}", timeout=2) as r:
        return json.load(r)


def _ifname(end, dpid):
    return end.get("name") or f"{short(dpid)}-eth{int(str(end.get('port_no', 1)))}"


def load_topology():
    """Current topology + links that were seen before but are gone now."""
    try:
        switches = [s["dpid"] for s in ryu_get("switches")]
        if not switches:
            raise ValueError("Ryu returned no switches")
        now = set()
        with LOCK:
            for l in ryu_get("links"):
                a, b = l["src"]["dpid"], l["dst"]["dpid"]
                k = tuple(sorted((a, b)))
                now.add(k)
                KNOWN_LINKS[k] = {a: _ifname(l["src"], a), b: _ifname(l["dst"], b)}
            for h in ryu_get("hosts"):
                for ip in h.get("ipv4", []):
                    KNOWN_HOSTS[ip] = h["port"]["dpid"]
            known = set(KNOWN_LINKS)
            hosts = [{"ip": ip, "dpid": d} for ip, d in KNOWN_HOSTS.items()]
        return {"source": "ryu", "switches": sorted(set(switches) |
                {d for k in known for d in k}),
                "links": sorted(now), "all_links": sorted(known),
                "down": sorted(known - now), "hosts": hosts, "note": ""}
    except Exception as e:
        d = DEMO
        links = sorted(tuple(sorted(l)) for l in d["links"])
        return {"source": "demo", "switches": d["switches"], "links": links,
                "all_links": links, "down": [], "hosts": d["hosts"],
                "note": f"Ryu controller not reachable ({e}). Showing the "
                        f"built-in topology from topo.py."}


def link_list(t):
    return [[short(a), short(b), "down" if (a, b) in t["down"] else "up"]
            for a, b in t["all_links"]]


def set_link(name_a, name_b, action):
    """Bring a link down/up by toggling both switch-side interfaces."""
    if action not in ("down", "up"):
        raise ValueError("action must be 'down' or 'up'")
    load_topology()
    with LOCK:
        key = next((k for k in KNOWN_LINKS
                    if {short(k[0]), short(k[1])} == {name_a, name_b}), None)
        ifs = list(KNOWN_LINKS[key].values()) if key else []
    if not key:
        raise ValueError(f"Unknown link {name_a}-{name_b} "
                         "(only works with the live Ryu topology)")
    done = []
    for i in ifs:
        try:
            r = subprocess.run(["ip", "link", "set", i, action],
                               capture_output=True, text=True)
        except OSError as e:
            raise RuntimeError(f"cannot run 'ip' command: {e}")
        if r.returncode == 0:
            done.append(i)
    if not done:
        raise RuntimeError(f"Could not set {ifs} {action} - run the dashboard "
                           f"with sudo from the machine running Mininet.")
    return {"link": [name_a, name_b], "action": action, "interfaces": done}


def build_graph(topo):
    g = {s: set() for s in topo["switches"]}
    for a, b in topo["links"]:
        g[a].add(b)
        g[b].add(a)
    return g


def host_switch(topo, ip):
    for h in topo["hosts"]:
        if h["ip"] == ip:
            return h["dpid"]
    return None


def all_paths(g, a, b, limit=20):
    """All simple switch-level paths a->b, shortest first (DFS)."""
    out = []

    def dfs(node, path):
        if len(out) >= limit * 5:
            return
        if node == b:
            out.append(list(path))
            return
        for n in sorted(g[node]):
            if n not in path:
                path.append(n)
                dfs(n, path)
                path.pop()
    dfs(a, [a])
    out.sort(key=len)
    return out[:limit]


def bfs(g, a, b):
    q, seen = deque([[a]]), {a}
    while q:
        p = q.popleft()
        if p[-1] == b:
            return p
        for n in g[p[-1]]:
            if n not in seen:
                seen.add(n)
                q.append(p + [n])
    return None


# ------------------------------------------------------------------- probe
def find_mininet_pid(host):
    try:
        out = subprocess.run(["pgrep", "-f", f"mininet:{host}$"],
                             capture_output=True, text=True, timeout=3).stdout
        pids = out.split()
        return pids[0] if pids else None
    except Exception:
        return None


def in_host(cmd):
    """Prefix `cmd` so it runs inside the Mininet host if possible; returns (cmd, where)."""
    pid = find_mininet_pid(CFG["mn_host"]) if shutil.which("mnexec") else None
    if pid and not CFG["local_probe"]:
        return ["mnexec", "-a", pid] + cmd, f"mininet:{CFG['mn_host']}"
    return cmd, "local"


def run_probe(dst, count, interval=0.1, timeout=1.0):
    """Run udp_probe.py (from inside the Mininet host if possible)."""
    cmd, where = in_host([sys.executable, PROBE_SCRIPT, dst, str(count),
                          str(interval), str(timeout)])
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE,
                       timeout=count * (interval + timeout) + 15)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "udp_probe.py failed")
    res = json.loads(r.stdout)
    res["probe_origin"] = where
    return res


# ---------------------------------------------------------------- analysis
def est_rtt(path):
    """Expected RTT (ms) of a switch path from topo.py's configured link delays
    (2 directions x sum of link delays) plus any injected delay; None if unknown."""
    total = 0.0
    for a, b in zip(path, path[1:]):
        na, nb = short(a), short(b)
        d = sdn_control.base_delay(na, nb)
        if d is None:
            return None
        extra = sdn_control.IMPAIRED.get("%s-%s" % tuple(sorted((na, nb))), {}).get("delay", 0)
        total += d + extra
    return round(2 * total, 2)


def analyse(dst, count):
    probe = run_probe(dst, count)
    topo = load_topology()
    g_now = build_graph(topo)                       # links that are up right now
    g_all = build_graph({"switches": topo["switches"], "links": topo["all_links"]})
    down = set(topo["down"])
    down_names = [[short(a), short(b)] for a, b in sorted(down)]
    src_sw = host_switch(topo, CFG["src_ip"])
    dst_sw = host_switch(topo, dst)

    paths, primary, original, warn = [], None, None, []
    path_source = "inferred (BFS)"
    if src_sw is None or dst_sw is None:
        missing = CFG["src_ip"] if src_sw is None else dst
        warn.append(f"Host {missing} not found in topology - run pingall "
                    f"in Mininet so the controller learns the hosts.")
    else:
        primary = bfs(g_now, src_sw, dst_sw)        # path available now (inferred)
        ctrl = sdn_control.read_state()
        key = f"{CFG['src_ip']}->{dst}"
        if ctrl and key in ctrl.get("paths", {}):   # dynamic app: the path really programmed
            cp = ctrl["paths"][key]
            primary = [full(x) for x in cp] if cp else None
            path_source = "controller"
        original = bfs(g_all, src_sw, dst_sw)       # path when nothing is down
        paths = all_paths(g_all, src_sw, dst_sw)

    loss, avg = probe["loss_pct"], probe["rtt_avg_ms"]
    route = " -> ".join(short(d) for d in primary) if primary else "unknown path"
    rerouted = bool(primary and original and primary != original)
    cause = ""
    if src_sw and dst_sw and primary is None:
        status = "failed"
        diag = "Path FAILED - no route in the topology"
        cause = ("Topology is disconnected: failed link(s) " +
                 ", ".join("-".join(x) for x in down_names) +
                 " left no route between the hosts.") if down_names else \
                "No route between the hosts in the controller's topology."
    elif loss == 100:
        status = "failed"
        diag = "Path FAILED - no replies received"
        cause = ("Controller still sees a route, but nothing came back: the "
                 "destination UDP echo server may be down, or the switches "
                 "are not forwarding (flows missing / stale after a failure).")
        if probe.get("errors"):
            cause += " Socket error: " + probe["errors"][0]
    elif loss > 0:
        status = "degraded"
        diag = "DEGRADED path - packet loss on " + route
        cause = "Partial loss on the active path: congestion, a lossy link, or a link that is flapping."
    else:
        status = "healthy"
        diag = "Path healthy"
    if rerouted and status != "failed":
        diag += " (rerouted around failed link)"
        cause = ("Original path " + " -> ".join(short(d) for d in original) +
                 " is down; traffic now uses " + route + ".")

    # Per-link RTT estimate (assumes equal delay on every inter-switch link) - only
    # used when topo.py's real per-link delays are not available.
    per_link = None
    if primary and len(primary) > 1 and probe["rtt_min_ms"] is not None:
        per_link = probe["rtt_min_ms"] / (len(primary) - 1)

    plist = []
    for p in paths:
        bad = [[short(a), short(b)] for a, b in zip(p, p[1:])
               if tuple(sorted((a, b))) in down]
        is_primary = (p == primary)
        if bad:
            st = "failed"
        elif is_primary:
            st = status
        else:
            st = "available"
        plist.append({
            "names": [short(d) for d in p], "hops": len(p), "primary": is_primary,
            "status": st, "down_links": bad,
            "measured_rtt_ms": avg if is_primary else None,
            "est_rtt_ms": est_rtt(p) if est_rtt(p) is not None else
                          (round(per_link * (len(p) - 1), 2) if per_link else None),
        })
    plist.sort(key=lambda x: (x["status"] == "failed", x["hops"]))

    suspects = []
    if status != "healthy":
        if down_names:
            suspects = down_names
        elif primary:
            suspects = [[short(a), short(b)] for a, b in zip(primary, primary[1:])]
    recommend = None
    if status != "healthy":
        alt = next((p for p in plist if p["status"] == "available"), None)
        if alt:
            recommend = " -> ".join(alt["names"])
        elif down_names:
            recommend = "No working alternative - restore " + \
                        ", ".join("-".join(x) for x in down_names)
        else:
            recommend = "No alternative path exists (redundant link needed)."

    result = {
        "time": time.strftime("%H:%M:%S"),
        "src": CFG["src_ip"], "dst": dst, "probe": probe,
        "status": status, "diagnosis": diag, "cause": cause, "warnings": warn,
        "rerouted": rerouted, "down_links": down_names,
        "topology": {
            "source": topo["source"], "note": topo["note"],
            "switches": [short(s) for s in topo["switches"]],
            "links": link_list(topo),
            "hosts": [{"ip": h["ip"], "switch": short(h["dpid"])}
                      for h in topo["hosts"]],
        },
        "primary": [short(d) for d in primary] if primary else None,
        "path_source": path_source,
        "paths": plist, "suspect_links": suspects, "recommend": recommend,
    }
    with LOCK:
        HISTORY.append({"time": result["time"], "dst": dst, "status": status,
                        "loss_pct": loss, "rtt_avg_ms": avg,
                        "jitter_ms": probe["jitter_ms"],
                        "path": " -> ".join(result["primary"] or []) or "n/a"})
        del HISTORY[:-50]
    return result


# ------------------------------------------------- dynamic SDN operations
def _hosts_for(dst):
    topo = load_topology()
    src_sw, dst_sw = host_switch(topo, CFG["src_ip"]), host_switch(topo, dst)
    if src_sw is None or dst_sw is None:
        raise ValueError("source or destination host not known to the controller - run pingall")
    return topo, src_sw, dst_sw


def measure_paths(dst, count=15):
    """Pin every loop-free path in turn, probe it, and compare MEASURED values.
    Leaves the controller with no pins (default routing) afterwards."""
    if sdn_control.read_state() is None:
        raise RuntimeError("dynamic controller app not running (start dynamic_path_app.py)")
    topo, a, b = _hosts_for(dst)
    paths = all_paths(build_graph(topo), a, b)
    if not paths:
        raise ValueError("no working path between the hosts")
    rows = []
    try:
        for p in paths:
            names = [short(x) for x in p]
            pol = sdn_control.set_policy([names])
            actual = pol["paths"].get(f"{CFG['src_ip']}->{dst}")
            row = {"names": names, "hops": len(p), "est_rtt_ms": est_rtt(p),
                   "pinned": bool(pol["applied"] and actual == names)}
            if row["pinned"]:
                pr = run_probe(dst, count, 0.05, 0.5)
                row.update(measured_rtt_ms=pr["rtt_avg_ms"], min_rtt_ms=pr["rtt_min_ms"],
                           jitter_ms=pr["jitter_ms"], loss_pct=pr["loss_pct"])
            else:
                row["error"] = "controller did not apply this path (got %s)" % actual
            rows.append(row)
    finally:
        sdn_control.set_policy([])
    ok = [r for r in rows if r.get("measured_rtt_ms") is not None]
    best = min(ok, key=lambda r: (r["loss_pct"], r["measured_rtt_ms"]), default=None)
    hop_choice = min(rows, key=lambda r: r["hops"]) if rows else None
    if best:
        best["best"] = True
    return {"time": time.strftime("%H:%M:%S"), "src": CFG["src_ip"], "dst": dst,
            "paths": rows, "best": best["names"] if best else None,
            "fewest_hops": hop_choice["names"] if hop_choice else None,
            "hop_count_choice_is_best": bool(best and hop_choice and best["names"] == hop_choice["names"])}


def apply_policy(action, path=None):
    if sdn_control.read_state() is None:
        raise RuntimeError("dynamic controller app not running (start dynamic_path_app.py)")
    if action == "clear":
        return sdn_control.set_policy([])
    if action == "apply" and isinstance(path, list) and len(path) >= 2:
        return sdn_control.set_policy([[str(x) for x in path]])
    raise ValueError("action must be 'clear' or 'apply' (with a path like ['s1','s2','s3'])")


def failover_test(dst, link, duration=10.0, fail_at=3.0, restore_at=7.0, interval=0.02):
    """Stream UDP probes, fail a link mid-run, restore it, and report the outage."""
    if not (0 < fail_at < restore_at < duration):
        raise ValueError("need 0 < fail_at < restore_at < duration")
    a, b = str(link[0]), str(link[1])
    before = sdn_control.read_state()
    cmd, where = in_host([sys.executable, os.path.join(HERE, "udp_stream_probe.py"),
                          dst, str(duration), str(interval), "0.5"])
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=HERE)
    t_start, t_fail, t_restore, err = time.time(), None, None, None
    try:
        time.sleep(fail_at)
        t_fail = time.time()
        set_link(a, b, "down")
        time.sleep(max(0, restore_at - fail_at))
        t_restore = time.time()
    except Exception as e:
        err = str(e)
    finally:
        try:
            set_link(a, b, "up")                      # always restore
        except Exception as e:
            err = err or str(e)
    out, errout = proc.communicate(timeout=duration * 2 + 20)
    if proc.returncode != 0:
        raise RuntimeError(errout.strip() or "udp_stream_probe.py failed")
    res = json.loads(out)
    if err:
        res["warning"] = err
    st = sdn_control.read_state()
    detect_ms, reroute_ms = sdn_control.reaction_times((st or {}).get("events"), t_fail) \
        if (st and t_fail) else (None, None)
    res.update(link=[a, b], probe_origin=where, fail_at_s=fail_at, restore_at_s=restore_at,
               controller_detect_ms=detect_ms, controller_reroute_ms=reroute_ms,
               controller_available=bool(st),
               path_after=(st or {}).get("paths", {}).get(f"{CFG['src_ip']}->{dst}"))
    return res


# -------------------------------------------------------------------- http
class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=STATIC, **kw)

    def log_message(self, fmt, *args):
        sys.stderr.write("[web] " + fmt % args + "\n")

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/topology"):
            t = load_topology()
            return self.send_json({
                "source": t["source"], "note": t["note"],
                "src_ip": CFG["src_ip"],
                "switches": [short(s) for s in t["switches"]],
                "links": link_list(t),
                "hosts": [{"ip": h["ip"], "switch": short(h["dpid"])}
                          for h in t["hosts"]]})
        if self.path.startswith("/api/state"):
            st = sdn_control.read_state()
            return self.send_json({"controller": st, "dynamic": st is not None,
                                   "impaired": sdn_control.IMPAIRED,
                                   "links_meta": sdn_control.read_meta()})
        if self.path.startswith("/api/history"):
            with LOCK:
                return self.send_json(HISTORY)
        return super().do_GET()

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def dynamic_post(self, req):
        try:
            if self.path.startswith("/api/measure"):
                dst = str(ipaddress.ip_address(req.get("dst", "")))
                return self.send_json(measure_paths(dst, max(3, min(int(req.get("count", 15)), 100))))
            if self.path.startswith("/api/policy"):
                return self.send_json(apply_policy(str(req.get("action")), req.get("path")))
            if self.path.startswith("/api/impair"):
                return self.send_json(sdn_control.impair(
                    str(req.get("a")), str(req.get("b")),
                    float(req.get("loss", 0)), float(req.get("delay", 0))))
            dst = str(ipaddress.ip_address(req.get("dst", "")))
            link = req.get("link") or []
            if len(link) != 2:
                raise ValueError("link must be [a, b], e.g. ['s1','s2']")
            return self.send_json(failover_test(
                dst, link, float(req.get("duration", 10)),
                float(req.get("fail_at", 3)), float(req.get("restore_at", 7))))
        except (ValueError, TypeError) as e:
            self.send_json({"error": str(e)}, 400)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def do_POST(self):
        try:
            req = self._body()
        except Exception:
            return self.send_json({"error": "Bad JSON"}, 400)
        if self.path.startswith("/api/link"):
            try:
                return self.send_json(set_link(str(req.get("a")), str(req.get("b")),
                                               str(req.get("action"))))
            except ValueError as e:
                return self.send_json({"error": str(e)}, 400)
            except Exception as e:
                return self.send_json({"error": str(e)}, 500)
        if self.path.startswith("/api/reset"):
            with LOCK:
                KNOWN_LINKS.clear(); KNOWN_HOSTS.clear(); HISTORY.clear()
            return self.send_json({"ok": True})
        if self.path.startswith(("/api/measure", "/api/policy", "/api/impair", "/api/failover")):
            return self.dynamic_post(req)
        if not self.path.startswith("/api/diagnose"):
            return self.send_json({"error": "not found"}, 404)
        try:
            dst = str(ipaddress.ip_address(req.get("dst", "")))
            count = max(1, min(int(req.get("count", 20)), 200))
        except Exception:
            return self.send_json({"error": "Invalid destination IP or count"}, 400)
        try:
            self.send_json(analyse(dst, count))
        except subprocess.TimeoutExpired:
            self.send_json({"error": "Probe timed out"}, 500)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--ryu", default="http://127.0.0.1:8080/v1.0/topology")
    ap.add_argument("--src-ip", default="10.0.0.1")
    ap.add_argument("--mn-host", default="h1",
                    help="Mininet host to send probes from (default h1)")
    ap.add_argument("--local-probe", action="store_true",
                    help="send probes from this machine, not from a Mininet host")
    a = ap.parse_args()
    CFG.update(ryu=a.ryu.rstrip("/"), src_ip=a.src_ip,
               mn_host=a.mn_host, local_probe=a.local_probe)
    print(f"Dashboard: http://{a.bind}:{a.port}   (Ryu API: {CFG['ryu']})")
    ThreadingHTTPServer((a.bind, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
