#!/usr/bin/env python3
"""
Integration test for the dashboard's dynamic-SDN features, without Mininet/Ryu:
a fake Ryu REST server + a fake controller (reads the policy file, writes the state file)
+ a real UDP echo server on 127.0.0.1.   Run:  python3 tests/test_dashboard_integration.py
"""
import json, os, subprocess, sys, tempfile, threading, time, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

TMP = tempfile.mkdtemp()
os.environ.update(SDN_STATE_FILE=TMP + "/state.json", SDN_POLICY_FILE=TMP + "/policy.json",
                  SDN_TOPO_META=TMP + "/meta.json")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import sdn_control, dashboard_server as ds           # noqa: E402

d = lambda i: "%016x" % i
PAIRS = [(1, 2), (2, 3), (1, 3)]
DOWN = set()
DST = "127.0.0.1"
EVENTS, STATE = [], {"seq": 0, "pins": []}


class FakeRyu(BaseHTTPRequestHandler):
    def do_GET(s):
        links = []
        for a, b in PAIRS:
            if (a, b) in DOWN:
                continue
            e = lambda x, y: {"src": {"dpid": d(x), "name": "s%d-eth%d" % (x, y)},
                              "dst": {"dpid": d(y), "name": "s%d-eth%d" % (y, x)}}
            links += [e(a, b), e(b, a)]
        data = {"switches": [{"dpid": d(i)} for i in (1, 2, 3)], "links": links,
                "hosts": [{"ipv4": ["10.0.0.1"], "port": {"dpid": d(1)}},
                          {"ipv4": [DST], "port": {"dpid": d(3)}}]}[s.path.rsplit("/", 1)[1]]
        b = json.dumps(data).encode()
        s.send_response(200); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)

    def log_message(*a):
        pass


def write_state():
    if STATE["pins"]:
        path = ["s%d" % x for x in STATE["pins"][0]]
    else:
        path = ["s1", "s3"] if (1, 3) not in DOWN else ["s1", "s2", "s3"]
    st = {"updated": time.time(), "policy_seq": STATE["seq"], "pins": [], "paths": {
        "10.0.0.1->" + DST: path, DST + "->10.0.0.1": path[::-1]}, "events": EVENTS[-60:]}
    json.dump(st, open(TMP + "/state.json.tmp", "w")); os.replace(TMP + "/state.json.tmp", TMP + "/state.json")


def fake_controller():
    last = None
    while True:
        try:
            m = os.stat(sdn_control.POLICY_FILE).st_mtime_ns
            if m != last:
                last = m
                p = json.load(open(sdn_control.POLICY_FILE))
                STATE.update(seq=p["seq"], pins=p["pins"]); write_state()
        except (OSError, ValueError):
            pass
        time.sleep(0.05)


def fake_set_link(a, b, action):
    pair = tuple(sorted((int(a[1:]), int(b[1:]))))
    (DOWN.add if action == "down" else DOWN.discard)(pair)
    if action == "down":
        EVENTS.append({"t": time.time(), "msg": "topology event: EventLinkDelete"})
        time.sleep(0.05)
        EVENTS.append({"t": time.time(), "msg": "flows reinstalled (topology change) in 1.0 ms"})
    write_state()
    return {}


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        json.dump([{"a": "s1", "b": "s2", "if_a": "s1-eth2", "if_b": "s2-eth2", "delay_ms": 10},
                   {"a": "s2", "b": "s3", "if_a": "s2-eth3", "if_b": "s3-eth2", "delay_ms": 10},
                   {"a": "s1", "b": "s3", "if_a": "s1-eth3", "if_b": "s3-eth3", "delay_ms": 30}],
                  open(TMP + "/meta.json", "w"))
        srv = HTTPServer(("127.0.0.1", 18080), FakeRyu)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        threading.Thread(target=fake_controller, daemon=True).start()
        write_state()
        cls.echo = subprocess.Popen([sys.executable, os.path.join(HERE, "..", "udp_server.py"), "9999"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        ds.CFG.update(ryu="http://127.0.0.1:18080/v1.0/topology", src_ip="10.0.0.1",
                      mn_host="h1", local_probe=True)
        ds.set_link = fake_set_link

    @classmethod
    def tearDownClass(cls):
        cls.echo.terminate()

    def test_1_analyse_uses_controller_path(self):
        r = ds.analyse(DST, 3)
        self.assertEqual(r["path_source"], "controller")
        self.assertEqual(r["primary"], ["s1", "s3"])
        self.assertEqual(r["status"], "healthy")
        est = {tuple(p["names"]): p["est_rtt_ms"] for p in r["paths"]}
        self.assertEqual(est[("s1", "s3")], 60.0)           # 2 x 30 ms
        self.assertEqual(est[("s1", "s2", "s3")], 40.0)     # 2 x (10+10)

    def test_2_measure_paths_and_cleanup(self):
        r = ds.measure_paths(DST, 4)
        self.assertEqual(len(r["paths"]), 2)
        self.assertTrue(all(p["pinned"] for p in r["paths"]), r)
        self.assertEqual(r["fewest_hops"], ["s1", "s3"])
        self.assertIsNotNone(r["best"])
        self.assertEqual(STATE["pins"], [])                  # pins cleared afterwards

    def test_3_policy_apply_clear(self):
        out = ds.apply_policy("apply", ["s1", "s2", "s3"])
        self.assertTrue(out["applied"])
        self.assertEqual(out["paths"]["10.0.0.1->" + DST], ["s1", "s2", "s3"])
        self.assertEqual(STATE["pins"], [[1, 2, 3], [3, 2, 1]])
        self.assertTrue(ds.apply_policy("clear")["applied"])
        with self.assertRaises(ValueError):
            ds.apply_policy("bogus")

    def test_4_impair_commands(self):
        calls = []
        fake = lambda cmd, **kw: (calls.append(cmd), subprocess.CompletedProcess(cmd, 0, "", ""))[1]
        sdn_control.impair("s1", "s2", 5, 20, run=fake)
        self.assertEqual(calls[0], ["tc", "qdisc", "replace", "dev", "s1-eth2", "root", "netem",
                                    "delay", "30ms", "loss", "5%"])
        self.assertEqual(len(calls), 2)
        self.assertIn("s1-s2", sdn_control.IMPAIRED)
        sdn_control.impair("s1", "s2", 0, 0, run=fake)
        self.assertNotIn("s1-s2", sdn_control.IMPAIRED)
        for bad in ((150, 0), (0, -1)):
            with self.assertRaises(ValueError):
                sdn_control.impair("s1", "s2", *bad, run=fake)
        with self.assertRaises(ValueError):
            sdn_control.impair("s1", "s9", 1, 1, run=fake)

    def test_5_failover(self):
        r = ds.failover_test(DST, ["s1", "s3"], duration=3, fail_at=1, restore_at=2, interval=0.05)
        self.assertEqual(r["controller_available"], True)
        self.assertIsNotNone(r["controller_detect_ms"])
        self.assertIsNotNone(r["controller_reroute_ms"])
        self.assertEqual(r["sent"], 60)
        self.assertEqual(DOWN, set())                        # link restored at the end

    def test_6_bad_failover_args(self):
        with self.assertRaises(ValueError):
            ds.failover_test(DST, ["s1", "s3"], duration=3, fail_at=2, restore_at=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
