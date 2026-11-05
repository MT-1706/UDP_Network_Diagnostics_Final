import json, urllib.request
from collections import deque

API = "http://127.0.0.1:8080/v1.0/topology"
def get(p):
    try:
        return json.load(urllib.request.urlopen(f"{API}/{p}", timeout=3))
    except Exception as e:
        raise SystemExit(f"ERROR: cannot reach Ryu topology API at {API} ({e}). "
                         "Is the controller running with ryu.app.rest_topology?")

SRC_IP = "10.0.0.1"
try:
    probe = json.load(open("/tmp/probe_result.json"))
except (OSError, ValueError):
    raise SystemExit("ERROR: no valid /tmp/probe_result.json - run udp_probe.py first")
DST_IP = probe["dst"]

switches = [s["dpid"] for s in get("switches")]
links = get("links")
hosts = get("hosts")

graph = {s: set() for s in switches}
for l in links:
    if l["src"]["dpid"] in graph and l["dst"]["dpid"] in graph:
        graph[l["src"]["dpid"]].add(l["dst"]["dpid"])

def host_switch(ip):
    for h in hosts:
        if ip in h["ipv4"]:
            return h["port"]["dpid"]
    raise SystemExit(f"Host {ip} not found - run pingall first")

def bfs(a, b):
    q, seen = deque([[a]]), {a}
    while q:
        path = q.popleft()
        if path[-1] == b: return path
        for n in graph[path[-1]]:
            if n not in seen:
                seen.add(n); q.append(path + [n])
    return None

path = bfs(host_switch(SRC_IP), host_switch(DST_IP))
short = lambda d: "s" + str(int(d, 16))
route = " -> ".join(short(d) for d in path) if path else "NO PATH"

print("=== Network Diagnostic Report ===")
print(f"Topology: {len(switches)} switches, {len(links)//2} links, {len(hosts)} hosts")
print(f"Path {SRC_IP} -> {DST_IP}: {route}")
print(f"Hops (switches): {len(path) if path else 'n/a'}")
print(f"RTT min/avg/max: {probe['rtt_min_ms']}/{probe['rtt_avg_ms']}/{probe['rtt_max_ms']} ms")
print(f"Probes sent: {probe['sent']}")
print(f"Replies received: {probe['received']}")
print(f"Probes timed out: {probe['sent'] - probe['received']}")
print(f"Observed loss: {probe['loss_pct']}%")
print(f"Jitter: {probe['jitter_ms']} ms")
if not path:
    print("DIAGNOSIS: path FAILED - topology has no route (link/switch down)")
elif probe["loss_pct"] == 100:
    print("DIAGNOSIS: path FAILED - route exists but no replies (server down or forwarding broken)")
elif probe["loss_pct"] > 0:
    print("DIAGNOSIS: DEGRADED path - packet loss on", route)
else:
    print("DIAGNOSIS: path healthy")
