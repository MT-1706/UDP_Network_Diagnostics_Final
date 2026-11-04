#!/usr/bin/env python3

"""
REAL end-to-end test: Mininet + Open vSwitch + Ryu controller + dashboard.

Start Ryu first, then run:
    sudo python3 tests/e2e_mininet.py
    sudo python3 tests/e2e_mininet.py --userspace

Prints PASS/FAIL for each test.
Delay/loss tests are skipped if tc netem is unavailable.
"""

import json, os, subprocess, sys, time, urllib.request
from functools import partial

HERE = os.path.dirname(os.path.abspath(__file__))   # Get dir containing this test file
ROOT = os.path.join(HERE, "..")     # Get root project dir
sys.path.insert(0, ROOT)    # Add project root to Python's module search path


import topo 
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel


RESULTS = []    # Store result of every test (True = passed, False = failed)


# Record & display result of an indiv test
def check(name, ok, detail=""):
    RESULTS.append(ok)  # Save test result
    print(("PASS  " if ok else "FAIL  ") + name + (("  -> " + str(detail)) if detail and not ok else ""))


# Send HTTP rqsts to dashboard API
def api(path, body=None, timeout=120):
    # Construct HTTP rqst w/ optional JSON data
    req = urllib.request.Request("http://127.0.0.1:5000" + path, data=None if body is None else json.dumps(body).encode(), headers={"Content-Type": "application/json"})

    try:    # Send rqst read rspns
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)

    except urllib.error.HTTPError as e:
        return e.code, json.load(e)     # Return HTTP error status & response body


# Run UDP n.w. diagnosis from h1 to h2
def diagnose(n=8):
    return api("/api/diagnose", {"dst": "10.0.0.2", "count": n})[1]


# Main function that executes all network tests
def main():

    setLogLevel("warning")  # Display only warning-level Mininet logs

    # Select userspace OVS if requested; otherwise use normal kernel OVS
    sw = partial(OVSSwitch, datapath="user") if "--userspace" in sys.argv else OVSSwitch

    net = Mininet(controller=None, switch=sw, link=TCLink, autoSetMacs=True)    # Create mn n.w. w/out an automatic ctrl.r

    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)     # Connect mn to running Ryu ctrl.r

    h1, h2, h3 = (net.addHost(n, ip="10.0.0.%d/24" % i) for i, n in ((1, "h1"), (2, "h2"), (3, "h3")))  # Create 3 hosts w/ IP addrs in same subnet

    s1, s2, s3 = (net.addSwitch(n, protocols="OpenFlow13") for n in ("s1", "s2", "s3")) # Create 3 switches using OpenFlow 1.3

    net.addLink(h1, s1); net.addLink(h3, s2); net.addLink(h2, s3)    # Connect each host to its corresponding switch

    net.addLink(s1, s2, delay="10ms"); net.addLink(s2, s3, delay="10ms"); net.addLink(s1, s3, delay="30ms")  # Create inter-switch links with different delays

    net.start() # Start the mn n.w.

    dash = None  # Store dashboard process reference for cleanup

    try:
        topo.write_meta(net)    # Save topology metadata for dashboard

        topo.disable_offload(net)   # Disable n.w. offloading for accurate pkt measurements

        time.sleep(5)   # Allow switches & ctrl.r to establish connections

        net.pingAll()   # Test host connectivity & allow ctrl.r to learn hosts
        loss = net.pingAll()

        # Verify that all hosts can communicate w/out pkt loss
        check("pingall (controller learns hosts, installs flows)", loss == 0, "%s%% dropped" % loss)

        h2.cmd("python3 %s/udp_server.py > /tmp/echo.log 2>&1 &" % ROOT)    # Start UDP echo server on h2 in bg

        # Start dashboard server as a separate process
        dash = subprocess.Popen([sys.executable, os.path.join(ROOT, "dashboard_server.py")], cwd=ROOT, stdout=open("/tmp/dash.log", "w"), stderr=subprocess.STDOUT)

        time.sleep(2)    # Wait for dashboard startup

        t = api("/api/topology")[1]     # Fetch curr n.w. topology from dashboard

        # Verify dashboard rcv.s live topology from Ryu
        check("dashboard sees live Ryu topology with 3 links", t["source"] == "ryu" and len(t["links"]) == 3, t)

        d = diagnose()  # Run network diagnosis

        # Verify UDP probes from h1 to h2 have 0 pkt loss
        check("UDP probe h1->h2 works (0% loss)", d["probe"]["loss_pct"] == 0, d["probe"])   

        # Verify path is obtained from ctrl.r
        check("path comes from the controller", d["path_source"] == "controller" and d["primary"] == ["s1", "s3"], d["primary"])


        # --- Measure all available paths ---
        m = api("/api/measure", {"dst": "10.0.0.2", "count": 8})[1]     # Measure n.w. paths between h1 & h2

        # Verify both paths were pinned and successfully measured
        check("measure every path: both pinned and measured", len(m.get("paths", [])) == 2 and all(p.get("pinned") and p.get("measured_rtt_ms") is not None for p in m["paths"]), m)

        # Verify that temp path pins were removed afterwards
        check("pins cleared afterwards", api("/api/state")[1]["controller"]["pins"] == []) 


        # --- Test manual path pinning ---
        st, r = api("/api/policy", {"action": "apply", "path": ["s1", "s2", "s3"]})     # Apply policy forcing traffic thru s1 -> s2 -> s3

        d = diagnose()  # Run diagnosis again to check pinned route

        # Verify pinned path works w/out pkt loss
        check("pinned path s1-s2-s3 is used and works", d["primary"] == ["s1", "s2", "s3"] and d["probe"]["loss_pct"] == 0, d["primary"])

        api("/api/policy", {"action": "clear"}) # Remove manually config.d path


        # --- Test automatic failover ---
        # Temp.ly fail a link & measure recovery behaviour
        f = api("/api/failover", {"dst": "10.0.0.2", "link": ["s1", "s3"], "duration": 8, "fail_at": 2.5, "restore_at": 5.5})[1]

        # Verify outage duration is below 1 second and packet loss below 20%
        check("failover: traffic recovered (outage < 1 s, loss < 20 %)", f.get("longest_outage_ms") is not None and f["longest_outage_ms"] < 1000 and f["loss_pct"] < 20, f)

        # Verify ctrl.r detection & rerouting times were recorded
        check("failover: controller reaction measured", f.get("controller_detect_ms") is not None and f.get("controller_reroute_ms") is not None, f)

        # Display measured outage & ctrl.r reaction times
        print("      outage %s ms, controller detected after %s ms, flows reprogrammed after %s ms"
              % (f.get("longest_outage_ms"), f.get("controller_detect_ms"), f.get("controller_reroute_ms")))

        time.sleep(3)   # Allow n.w. to stabilise after failover

        # --- Test failure of the direct s1-s3 link ---
        api("/api/link", {"a": "s1", "b": "s3", "action": "down"})  # Bring direct link between s1 & s3 down

        time.sleep(2)   # Allow ctrl.r to detect link failure

        d = diagnose()  # Run diagnosis after link failure

        # Verify traffic is rerouted through s1 -> s2 -> s3
        check("s1-s3 down: rerouted via s2, still 0% loss", d["primary"] == ["s1", "s2", "s3"] and d["probe"]["loss_pct"] == 0 and d["down_links"] == [["s1", "s3"]], d["primary"])


        # --- Test complete network disconnection ---
        api("/api/link", {"a": "s2", "b": "s3", "action": "down"})  # Bring remaining s2-s3 link down

        time.sleep(2)    # Allow ctrl.r to update its topology

        d = diagnose(4)     # Run diagnosis w/ fewer UDP probes

        # Verify no route exists & both failed links are reported
        check("all paths down: reported as no route, failed links named", d["status"] == "failed" and d["primary"] is None and len(d["down_links"]) == 2, d["diagnosis"])


        # --- Restore network connectivity ---
        # Bring both failed links back up
        api("/api/link", {"a": "s2", "b": "s3", "action": "up"})
        api("/api/link", {"a": "s1", "b": "s3", "action": "up"})

        time.sleep(4)    # W8 for topology & routing tables to recover

        d = diagnose()   # Verify default shortest path is healthy again
        check("links restored: healthy on default path again", d["status"] == "healthy" and d["primary"] == ["s1", "s3"], d["primary"])


        # --- Test packet loss and delay injection ---
        st, r = api("/api/impair", {"a": "s1", "b": "s3", "loss": 20, "delay": 0})  # Inject 20% pkt loss on s1-s3 link

        if st == 200:
            d = diagnose(40)    # Run diagnosis w/ 40 probes to detect pkt loss

            # Verify that the UDP probe detects packet loss
            check("20 % loss injected: probe sees loss", d["probe"]["loss_pct"] > 0, d["probe"]["loss_pct"])

            api("/api/impair", {"a": "s1", "b": "s3", "loss": 0, "delay": 0})   # Remove injected pkt loss

            d = diagnose()  # Verify that packet loss returns to zero
            check("impairment cleared: 0 % loss", d["probe"]["loss_pct"] == 0, d["probe"]["loss_pct"])

        else:
            print("SKIP  loss/delay injection: " + str(r.get("error")))  # Skip impairment tests if traffic ctrl.r is unavail


    finally:
        if dash:    # Stop dashboard process if it was started
            dash.terminate()

        net.stop()  # Stop mn & clean up n.w.

    # Print overall test results
    print("\nALL %d CHECKS PASSED" % len(RESULTS) if all(RESULTS) else "\n%d of %d CHECKS FAILED" % (RESULTS.count(False), len(RESULTS)))

    # Exit with status 0 if all tests passed, otherwise 1
    sys.exit(0 if all(RESULTS) else 1)


# Run main() only when this file is executed directly
if __name__ == "__main__":
    main()