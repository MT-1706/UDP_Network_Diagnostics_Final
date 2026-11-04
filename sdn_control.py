"""
Helpers that let the dashboard talk to the *dynamic* SDN controller app
(dynamic_path_app.py) and to the emulated links.  Standard library only.

  read_state()   - controller's own view (verified paths, events)  <- /tmp/sdn_state.json
  set_policy()   - ask the controller to pin paths                 -> /tmp/sdn_policy.json
  impair()       - add loss / extra delay to a link with tc netem
"""
import json, os, subprocess, time

STATE_FILE = os.environ.get("SDN_STATE_FILE", "/tmp/sdn_state.json")
POLICY_FILE = os.environ.get("SDN_POLICY_FILE", "/tmp/sdn_policy.json")
META_FILE = os.environ.get("SDN_TOPO_META", "/tmp/sdn_topo_meta.json")

IMPAIRED = {}          # "s1-s2" -> {"loss": %, "delay": extra ms}
_seq = [int(time.time())]


def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def read_state():
    """Controller state dict, or None if the dynamic app is not running."""
    return _read_json(STATE_FILE)


def read_meta():
    """[{a,b,if_a,if_b,delay_ms}] written by topo.py, or []."""
    m = _read_json(META_FILE)
    return m if isinstance(m, list) else []


def link_meta(a, b):
    for m in read_meta():
        if {m["a"], m["b"]} == {a, b}:
            return m
    return None


def base_delay(a, b):
    m = link_meta(a, b)
    return float(m["delay_ms"]) if m else None


def _dpid(name):
    return int(str(name).lstrip("s"))


def set_policy(paths, wait=5.0):
    """Pin each path in `paths` (list of ['s1','s2','s3']) in BOTH directions.
    [] clears all pins.  Returns {'applied': bool, 'seq': n, 'paths': controller paths}."""
    pins = []
    for p in paths:
        ids = [_dpid(x) for x in p]
        pins += [ids, ids[::-1]]
    _seq[0] += 1
    seq = _seq[0]
    tmp = POLICY_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"seq": seq, "pins": pins}, f)
    os.replace(tmp, POLICY_FILE)                      # atomic: controller never sees half a file
    t0, st = time.time(), None
    while time.time() - t0 < wait:
        st = read_state()
        if st and st.get("policy_seq") == seq:
            time.sleep(0.2)                           # let flow-mods reach the switches
            return {"applied": True, "seq": seq, "paths": read_state().get("paths", {})}
        time.sleep(0.1)
    return {"applied": False, "seq": seq, "paths": (st or {}).get("paths", {})}


def netem_args(base_ms, extra_ms, loss_pct):
    args = ["delay", "%gms" % (base_ms + extra_ms)]
    if loss_pct > 0:
        args += ["loss", "%g%%" % loss_pct]
    return args


def impair(a, b, loss_pct=0.0, extra_delay_ms=0.0, run=subprocess.run):
    """Set loss / extra delay on link a-b (both switch-side interfaces).
    loss=0 and extra=0 restores the link's original delay."""
    if not (0 <= loss_pct <= 100) or not (0 <= extra_delay_ms <= 2000):
        raise ValueError("loss must be 0-100 % and extra delay 0-2000 ms")
    m = link_meta(a, b)
    if not m:
        raise ValueError("Unknown link %s-%s (is topo.py running? it writes %s)" % (a, b, META_FILE))
    done = []
    for ifname in (m["if_a"], m["if_b"]):
        try:
            r = run(["tc", "qdisc", "replace", "dev", ifname, "root", "netem"] +
                    netem_args(m["delay_ms"], extra_delay_ms, loss_pct),
                    capture_output=True, text=True)
        except OSError as e:
            raise RuntimeError("cannot run 'tc': %s" % e)
        if r.returncode == 0:
            done.append(ifname)
        else:
            last = r.stderr.strip()
    if not done:
        hint = (" Your kernel has no 'netem' module: try 'sudo modprobe sch_netem' (not available in some VMs/containers)."
                if "unknown" in last.lower() else " Run the dashboard with sudo on the Mininet machine.")
        raise RuntimeError("tc failed (%s).%s" % (last, hint))
    key = "%s-%s" % tuple(sorted((a, b)))
    if loss_pct or extra_delay_ms:
        IMPAIRED[key] = {"loss": loss_pct, "delay": extra_delay_ms}
    else:
        IMPAIRED.pop(key, None)
    return {"link": [a, b], "loss_pct": loss_pct, "extra_delay_ms": extra_delay_ms, "interfaces": done}


def reaction_times(events, t_fail):
    """From controller events: seconds from the failure to (a) the controller noticing the
    link went down and (b) flows being reprogrammed."""
    seen = reroute = None
    for e in events or []:
        if e["t"] < t_fail - 0.05:
            continue
        if seen is None and "LinkDelete" in e["msg"]:
            seen = e["t"] - t_fail
        if seen is not None and reroute is None and "flows reinstalled" in e["msg"]:
            reroute = e["t"] - t_fail
    return (None if seen is None else round(seen * 1000, 1),
            None if reroute is None else round(reroute * 1000, 1))
