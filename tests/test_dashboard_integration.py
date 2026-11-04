#!/usr/bin/env python3

"""
Integration test for dashboard dynamic-SDN features without Mininet/Ryu.

Uses:
- Fake Ryu REST server
- Fake controller
- Real UDP echo server

Run: python3 tests/test_dashboard_integration.py
"""

import json, os, subprocess, sys, tempfile, threading, time, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

TMP = tempfile.mkdtemp()    # Create a temp dir for test files

# Set temp paths for ctrl.r state, policy & topology metadata
os.environ.update(SDN_STATE_FILE=TMP + "/state.json", SDN_POLICY_FILE=TMP + "/policy.json", SDN_TOPO_META=TMP + "/meta.json")
HERE = os.path.dirname(os.path.abspath(__file__))   # Get dir containing this test file
sys.path.insert(0, os.path.join(HERE, ".."))    #  Add proj root to Python's module search path

import sdn_control, dashboard_server as ds 

d = lambda i: "%016x" % i   # conv a switch ID into 16-char hexadecimal DPID
PAIRS = [(1, 2), (2, 3), (1, 3)]    # Define 3 physical links in n.w.

DOWN = set()    # Store links that are currently down   
DST = "127.0.0.1"   # Dest addr used by UDP echo server

# Store ctrl.r events & curr policy info
EVENTS, STATE = [], {"seq": 0, "pins": []}

# Simulate Ryu's REST API using a local HTTP server
class FakeRyu(BaseHTTPRequestHandler):
    # Handle incoming GET requests from the dashboard
    def do_GET(s):

        links = []  # Store currently active network links

        # Generate link information for every active connection
        for a, b in PAIRS:

            if (a, b) in DOWN:
                continue  # Skip links that are currently down

            # Create a directed link description between two switches
            e = lambda x, y: {"src": {"dpid": d(x), "name": "s%d-eth%d" % (x, y)},
                              "dst": {"dpid": d(y), "name": "s%d-eth%d" % (y, x)}}

            # Add both directions because links are bidirectional
            links += [e(a, b), e(b, a)]

        # Return the requested topology information
        data = {"switches": [{"dpid": d(i)} for i in (1, 2, 3)], "links": links,
                "hosts": [{"ipv4": ["10.0.0.1"], "port": {"dpid": d(1)}},
                          {"ipv4": [DST], "port": {"dpid": d(3)}}]}[s.path.rsplit("/", 1)[1]]

        # Convert response data into JSON bytes
        b = json.dumps(data).encode()

        # Send HTTP response with JSON content
        s.send_response(200)
        s.send_header("Content-Length", str(len(b)))
        s.end_headers()
        s.wfile.write(b)

    # Disable HTTP request logging
    def log_message(*a):
        pass


# Generate and save the simulated controller state
def write_state():

    # Use manually pinned path if one exists
    if STATE["pins"]:
        path = ["s%d" % x for x in STATE["pins"][0]]

    else:
        # Otherwise select the available default path
        path = ["s1", "s3"] if (1, 3) not in DOWN else ["s1", "s2", "s3"]

    # Build the controller state information
    st = {"updated": time.time(), "policy_seq": STATE["seq"], "pins": [], "paths": {
        "10.0.0.1->" + DST: path, DST + "->10.0.0.1": path[::-1]}, "events": EVENTS[-60:]}

    # Write state to a temporary file, then replace the old file
    json.dump(st, open(TMP + "/state.json.tmp", "w"))
    os.replace(TMP + "/state.json.tmp", TMP + "/state.json")


# Simulate a controller that continuously checks the policy file
def fake_controller():

    last = None  # Store the last observed modification timestamp

    while True:
        try:
            # Check whether the policy file has changed
            m = os.stat(sdn_control.POLICY_FILE).st_mtime_ns

            if m != last:
                last = m  # Update modification timestamp

                # Read the new policy configuration
                p = json.load(open(sdn_control.POLICY_FILE))

                # Update simulated controller state
                STATE.update(seq=p["seq"], pins=p["pins"])

                # Save the updated state
                write_state()

        except (OSError, ValueError):
            pass  # Ignore missing or temporarily invalid files

        time.sleep(0.05)  # Check again after 50 ms


# Simulate a network link going up or down
def fake_set_link(a, b, action):

    # Convert switch names into a sorted link identifier
    pair = tuple(sorted((int(a[1:]), int(b[1:]))))

    # Add failed links or remove restored links
    (DOWN.add if action == "down" else DOWN.discard)(pair)

    if action == "down":

        # Record the simulated topology change
        EVENTS.append({"t": time.time(), "msg": "topology event: EventLinkDelete"})

        time.sleep(0.05)  # Simulate controller processing delay

        # Record flow reinstallation event
        EVENTS.append({"t": time.time(), "msg": "flows reinstalled (topology change) in 1.0 ms"})

    # Update the controller state after changing the link
    write_state()

    return {}


# Define the dashboard integration test cases
class T(unittest.TestCase):

    # Run once before executing all test cases
    @classmethod
    def setUpClass(cls):

        # Save network topology metadata
        json.dump([{"a": "s1", "b": "s2", "if_a": "s1-eth2", "if_b": "s2-eth2", "delay_ms": 10},
                   {"a": "s2", "b": "s3", "if_a": "s2-eth3", "if_b": "s3-eth2", "delay_ms": 10},
                   {"a": "s1", "b": "s3", "if_a": "s1-eth3", "if_b": "s3-eth3", "delay_ms": 30}],
                  open(TMP + "/meta.json", "w"))

        # Start the fake Ryu REST server on port 18080
        srv = HTTPServer(("127.0.0.1", 18080), FakeRyu)

        # Run the REST server in a background thread
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        # Start the fake controller in a background thread
        threading.Thread(target=fake_controller, daemon=True).start()

        # Initialise the controller state file
        write_state()

        # Start the real UDP echo server on port 9999
        cls.echo = subprocess.Popen([sys.executable, os.path.join(HERE, "..", "udp_server.py"), "9999"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Allow the UDP server to start
        time.sleep(0.5)

        # Configure dashboard to use the fake Ryu server and local UDP probing
        ds.CFG.update(ryu="http://127.0.0.1:18080/v1.0/topology", src_ip="10.0.0.1",
                      mn_host="h1", local_probe=True)

        # Replace real link control with the simulated link function
        ds.set_link = fake_set_link

    # Run once after all test cases finish
    @classmethod
    def tearDownClass(cls):

        # Stop the UDP echo server
        cls.echo.terminate()


    # Test 1: Verify diagnosis uses the controller's selected path
    def test_1_analyse_uses_controller_path(self):

        # Analyse connectivity between source and destination
        r = ds.analyse(DST, 3)

        # Verify the path comes from the controller
        self.assertEqual(r["path_source"], "controller")

        # Verify the selected path is s1 -> s3
        self.assertEqual(r["primary"], ["s1", "s3"])

        # Verify network status is healthy
        self.assertEqual(r["status"], "healthy")

        # Calculate estimated RTT for each available path
        est = {tuple(p["names"]): p["est_rtt_ms"] for p in r["paths"]}

        # Direct path has two 30 ms links
        self.assertEqual(est[("s1", "s3")], 60.0)

        # Alternate path has two 10 ms links
        self.assertEqual(est[("s1", "s2", "s3")], 40.0)


    # Test 2: Verify path measurement and automatic cleanup
    def test_2_measure_paths_and_cleanup(self):

        # Measure all available paths to the destination
        r = ds.measure_paths(DST, 4)

        # Verify that two paths were discovered
        self.assertEqual(len(r["paths"]), 2)

        # Verify that both paths were temporarily pinned
        self.assertTrue(all(p["pinned"] for p in r["paths"]), r)

        # Verify the path with the fewest hops
        self.assertEqual(r["fewest_hops"], ["s1", "s3"])

        # Verify that the best measured path exists
        self.assertIsNotNone(r["best"])

        # Ensure temporary pins were cleared afterwards
        self.assertEqual(STATE["pins"], [])


    # Test 3: Verify manual path policy application and removal
    def test_3_policy_apply_clear(self):

        # Apply a policy forcing traffic through s1 -> s2 -> s3
        out = ds.apply_policy("apply", ["s1", "s2", "s3"])

        # Verify that the policy was successfully applied
        self.assertTrue(out["applied"])

        # Verify the selected path in controller state
        self.assertEqual(out["paths"]["10.0.0.1->" + DST], ["s1", "s2", "s3"])

        # Verify that forward and reverse paths are pinned
        self.assertEqual(STATE["pins"], [[1, 2, 3], [3, 2, 1]])

        # Clear the manually applied policy
        self.assertTrue(ds.apply_policy("clear")["applied"])

        # Verify invalid policy actions raise an error
        with self.assertRaises(ValueError):
            ds.apply_policy("bogus")


    # Test 4: Verify traffic impairment commands
    def test_4_impair_commands(self):

        calls = []  # Store executed traffic-control commands

        # Mock subprocess execution so actual system commands are not run
        fake = lambda cmd, **kw: (calls.append(cmd), subprocess.CompletedProcess(cmd, 0, "", ""))[1]

        # Apply 20 ms delay and 5% packet loss to the s1-s2 link
        sdn_control.impair("s1", "s2", 5, 20, run=fake)

        # Verify the generated tc netem command
        self.assertEqual(calls[0], ["tc", "qdisc", "replace", "dev", "s1-eth2", "root", "netem",
                                    "delay", "30ms", "loss", "5%"])

        # Verify commands were executed for both link directions
        self.assertEqual(len(calls), 2)

        # Verify the link is recorded as impaired
        self.assertIn("s1-s2", sdn_control.IMPAIRED)

        # Remove the applied delay and packet loss
        sdn_control.impair("s1", "s2", 0, 0, run=fake)

        # Verify the impairment record is removed
        self.assertNotIn("s1-s2", sdn_control.IMPAIRED)

        # Verify packet loss above 100% is rejected
        for bad in ((150, 0), (0, -1)):
            with self.assertRaises(ValueError):
                sdn_control.impair("s1", "s2", *bad, run=fake)

        # Verify unknown switch links are rejected
        with self.assertRaises(ValueError):
            sdn_control.impair("s1", "s9", 1, 1, run=fake)


    # Test 5: Verify automatic failover and recovery
    def test_5_failover(self):

        # Run failover test with link failure at 1 second and restoration at 2 seconds
        r = ds.failover_test(DST, ["s1", "s3"], duration=3, fail_at=1, restore_at=2, interval=0.05)

        # Verify that the controller was available during testing
        self.assertEqual(r["controller_available"], True)

        # Verify that controller detection time was recorded
        self.assertIsNotNone(r["controller_detect_ms"])

        # Verify that controller rerouting time was recorded
        self.assertIsNotNone(r["controller_reroute_ms"])

        # Verify that 60 UDP probes were sent
        self.assertEqual(r["sent"], 60)

        # Verify that the failed link was restored at the end
        self.assertEqual(DOWN, set())


    # Test 6: Verify invalid failover parameters are rejected
    def test_6_bad_failover_args(self):

        # Restoration time cannot be earlier than failure time
        with self.assertRaises(ValueError):
            ds.failover_test(DST, ["s1", "s3"], duration=3, fail_at=2, restore_at=1)


# Run all test cases when this file is executed directly
if __name__ == "__main__":
    unittest.main(verbosity=2)