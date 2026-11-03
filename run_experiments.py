#!/usr/bin/env python3
"""
Performance-evaluation runner.  Drives the running dashboard (which drives Mininet/Ryu)
and writes  results/*.csv  +  results/report.html  (charts included, no libraries needed).

Experiments
  E1  per-path comparison   : every loop-free path pinned and probed -> hops vs measured RTT
  E2  loss injection        : tc netem loss on a link of the active path -> measured vs expected loss
  E3  delay injection       : extra delay on that link -> measured vs expected RTT
  E4  failover              : fail a link mid-stream N times -> outage / detect / reflow times

usage (dashboard already running, Mininet + Ryu up, pingall done):
    sudo python3 run_experiments.py --dst 10.0.0.2 [--base http://127.0.0.1:5000]
         [--link s1-s3] [--count 40] [--trials 3] [--out results]
"""
import argparse, csv, html, json, os, statistics, sys, time, urllib.request


def call(base, path, body=None, timeout=180):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            msg = json.load(e).get("error", e.reason)
        except Exception:
            msg = e.reason
        raise RuntimeError("%s -> %s" % (path, msg))


def write_csv(out, name, rows):
    if not rows:
        return
    with open(os.path.join(out, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


# ------------------------------------------------------------------ experiments
def e1_paths(a):
    r = call(a.base, "/api/measure", {"dst": a.dst, "count": a.count})
    rows = [{"path": " > ".join(p["names"]), "hops": p["hops"], "expected_rtt_ms": p["est_rtt_ms"],
             "measured_rtt_ms": p.get("measured_rtt_ms"), "jitter_ms": p.get("jitter_ms"),
             "loss_pct": p.get("loss_pct")} for p in r["paths"]]
    return rows, r


def e2_loss(a, link):
    rows = []
    for p in a.loss_levels:
        call(a.base, "/api/impair", {"a": link[0], "b": link[1], "loss": p, "delay": 0})
        time.sleep(0.5)
        d = call(a.base, "/api/diagnose", {"dst": a.dst, "count": a.count * 2})
        # one-way loss p applies to each direction -> round trip survives with (1-p)^2
        exp = round(100 * (1 - (1 - p / 100) ** 2), 2)
        rows.append({"injected_loss_pct_per_direction": p, "expected_rtt_loss_pct": exp,
                     "measured_loss_pct": d["probe"]["loss_pct"], "probes": d["probe"]["sent"],
                     "status": d["status"]})
    call(a.base, "/api/impair", {"a": link[0], "b": link[1], "loss": 0, "delay": 0})
    return rows


def e3_delay(a, link):
    rows = []
    for extra in a.delay_levels:
        call(a.base, "/api/impair", {"a": link[0], "b": link[1], "loss": 0, "delay": extra})
        time.sleep(0.5)
        d = call(a.base, "/api/diagnose", {"dst": a.dst, "count": a.count})
        base = rows[0]["measured_rtt_ms"] if rows else d["probe"]["rtt_avg_ms"]
        rows.append({"extra_delay_ms_per_direction": extra,
                     "expected_rtt_ms": None if base is None else round(base + 2 * extra, 2),
                     "measured_rtt_ms": d["probe"]["rtt_avg_ms"], "jitter_ms": d["probe"]["jitter_ms"]})
    call(a.base, "/api/impair", {"a": link[0], "b": link[1], "loss": 0, "delay": 0})
    return rows


def e4_failover(a, link):
    rows = []
    for i in range(a.trials):
        r = call(a.base, "/api/failover", {"dst": a.dst, "link": list(link), "duration": 10,
                                           "fail_at": 3, "restore_at": 7})
        rows.append({"trial": i + 1, "outage_ms": r["longest_outage_ms"], "loss_pct": r["loss_pct"],
                     "controller_detect_ms": r["controller_detect_ms"],
                     "controller_reroute_ms": r["controller_reroute_ms"],
                     "path_after": " > ".join(r["path_after"] or [])})
        time.sleep(3)                                   # let LLDP rediscover the restored link
    return rows


# ------------------------------------------------------------------ report (inline SVG)
COLORS = ["#2a6fdb", "#e8833a", "#2f9e6b", "#8e5bd9"]


def bar_chart(title, cats, series, ylabel):
    """series = {name: [values]} ; None values drawn as gaps."""
    W, H, L, B, T = 640, 300, 56, 56, 34
    vals = [v for s in series.values() for v in s if v is not None]
    top = max(vals) * 1.15 if vals and max(vals) > 0 else 1
    pw, ph = W - L - 12, H - T - B
    grp = pw / max(1, len(cats))
    bw = grp * 0.7 / max(1, len(series))
    o = ['<svg viewBox="0 0 %d %d" role="img" aria-label="%s" class="chart">' % (W, H, html.escape(title)),
         '<text x="%d" y="20" class="ct">%s</text>' % (L, html.escape(title))]
    for i in range(5):
        y = T + ph - ph * i / 4
        o.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" class="grid"/>' % (L, W - 12, y, y))
        o.append('<text x="%d" y="%.1f" class="ax" text-anchor="end">%.3g</text>' % (L - 6, y + 4, top * i / 4))
    o.append('<text x="14" y="%d" class="ax" transform="rotate(-90 14 %d)" text-anchor="middle">%s</text>'
             % (T + ph / 2, T + ph / 2, html.escape(ylabel)))
    for ci, c in enumerate(cats):
        gx = L + ci * grp + grp * 0.15
        for si, (name, vs) in enumerate(series.items()):
            v = vs[ci]
            if v is None:
                continue
            h = ph * v / top
            x = gx + si * bw
            o.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s"><title>%s: %s = %s</title></rect>'
                     % (x, T + ph - h, bw - 2, h, COLORS[si % 4], html.escape(str(c)), html.escape(name), v))
            o.append('<text x="%.1f" y="%.1f" class="ax" text-anchor="middle">%.3g</text>'
                     % (x + bw / 2, T + ph - h - 4, v))
        o.append('<text x="%.1f" y="%d" class="ax" text-anchor="middle">%s</text>'
                 % (L + ci * grp + grp / 2, H - B + 18, html.escape(str(c))))
    for si, name in enumerate(series):
        o.append('<rect x="%d" y="%d" width="10" height="10" fill="%s"/><text x="%d" y="%d" class="ax">%s</text>'
                 % (L + si * 150, H - 16, COLORS[si % 4], L + si * 150 + 14, H - 7, html.escape(name)))
    o.append("</svg>")
    return "".join(o)


def table(rows):
    if not rows:
        return "<p>no data</p>"
    h = "".join("<th>%s</th>" % html.escape(k) for k in rows[0])
    b = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % html.escape("" if v is None else str(v))
                                        for v in r.values()) for r in rows)
    return "<table><tr>%s</tr>%s</table>" % (h, b)


def build_report(res, a, link):
    parts = ["<h1>Performance evaluation</h1><p>Destination %s &middot; impaired link %s &middot; %s</p>"
             % (a.dst, "-".join(link), time.strftime("%Y-%m-%d %H:%M"))]
    if res.get("e1"):
        r = res["e1"]
        parts.append("<h2>E1 - Path comparison (hops vs measured latency)</h2>")
        parts.append(bar_chart("RTT per path", [x["path"] for x in r],
                               {"expected (config)": [x["expected_rtt_ms"] for x in r],
                                "measured": [x["measured_rtt_ms"] for x in r]}, "RTT (ms)"))
        parts.append(table(r))
        ok = [x for x in r if x["measured_rtt_ms"] is not None]
        if ok:
            fewest = min(r, key=lambda x: x["hops"])
            best = min(ok, key=lambda x: x["measured_rtt_ms"])
            parts.append("<p><b>Finding:</b> fewest-hop path = %s (%s ms); lowest-latency path = %s (%s ms). %s</p>" % (
                fewest["path"], fewest["measured_rtt_ms"], best["path"], best["measured_rtt_ms"],
                "They differ - hop count alone is a poor metric." if fewest is not best else "They coincide."))
    if res.get("e2"):
        r = res["e2"]
        parts.append("<h2>E2 - Packet-loss injection</h2>")
        parts.append(bar_chart("Round-trip loss vs injected loss", [str(x["injected_loss_pct_per_direction"]) + " %" for x in r],
                               {"expected": [x["expected_rtt_loss_pct"] for x in r],
                                "measured": [x["measured_loss_pct"] for x in r]}, "loss (%)"))
        parts.append(table(r))
    if res.get("e3"):
        r = res["e3"]
        parts.append("<h2>E3 - Delay injection</h2>")
        parts.append(bar_chart("RTT vs injected delay", ["+%s ms" % x["extra_delay_ms_per_direction"] for x in r],
                               {"expected": [x["expected_rtt_ms"] for x in r],
                                "measured": [x["measured_rtt_ms"] for x in r]}, "RTT (ms)"))
        parts.append(table(r))
    if res.get("e4"):
        r = res["e4"]
        parts.append("<h2>E4 - Link-failure recovery</h2>")
        parts.append(bar_chart("Recovery per trial", ["trial %d" % x["trial"] for x in r],
                               {"service outage": [x["outage_ms"] for x in r],
                                "controller detect": [x["controller_detect_ms"] for x in r],
                                "flows reprogrammed": [x["controller_reroute_ms"] for x in r]}, "ms"))
        parts.append(table(r))
        outs = [x["outage_ms"] for x in r if x["outage_ms"] is not None]
        if outs:
            parts.append("<p><b>Mean outage:</b> %.0f ms (min %.0f, max %.0f) over %d trials.</p>"
                         % (statistics.mean(outs), min(outs), max(outs), len(outs)))
    if res.get("errors"):
        parts.append("<h2>Experiments that failed</h2><ul>%s</ul>" %
                     "".join("<li>%s: %s</li>" % (html.escape(k), html.escape(v)) for k, v in res["errors"].items()))
    css = ("body{font:15px system-ui;max-width:720px;margin:2rem auto;padding:0 16px;background:#fff;color:#1b1f24}"
           "table{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:13px}td,th{border:1px solid #ccd;padding:4px 8px;text-align:left}"
           ".chart{width:100%;height:auto}.grid{stroke:#d5d9df}.ax{font-size:11px;fill:#555}.ct{font-weight:600;font-size:14px;fill:#1b1f24}"
           "@media (prefers-color-scheme:dark){body{background:#14171c;color:#e6e8eb}td,th{border-color:#3a414b}.grid{stroke:#333a44}.ax{fill:#aab}.ct{fill:#e6e8eb}}")
    return "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Performance report</title><style>%s</style>%s" % (css, "".join(parts))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--dst", required=True)
    ap.add_argument("--base", default="http://127.0.0.1:5000")
    ap.add_argument("--link", help="link to impair / fail, e.g. s1-s3 (default: first link of the active path)")
    ap.add_argument("--count", type=int, default=40)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--loss-levels", type=float, nargs="+", default=[0, 5, 10, 20], dest="loss_levels")
    ap.add_argument("--delay-levels", type=float, nargs="+", default=[0, 10, 20, 40], dest="delay_levels")
    ap.add_argument("--out", default="results")
    ap.add_argument("--skip", nargs="*", default=[], choices=["e1", "e2", "e3", "e4"])
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    try:
        d = call(a.base, "/api/diagnose", {"dst": a.dst, "count": 5})
    except Exception as e:
        sys.exit("Cannot reach the dashboard / run a probe: %s" % e)
    if a.link:
        link = a.link.split("-")
    elif d.get("primary") and len(d["primary"]) > 1:
        link = d["primary"][:2]
    else:
        sys.exit("No inter-switch link on the active path; pass --link (e.g. s1-s3)")
    if len(link) != 2:
        sys.exit("--link must look like s1-s3")
    print("Active path:", " > ".join(d["primary"] or ["?"]), "| experiment link:", "-".join(link))

    res, errors = {}, {}
    steps = [("e1", lambda: e1_paths(a)[0]), ("e2", lambda: e2_loss(a, link)),
             ("e3", lambda: e3_delay(a, link)), ("e4", lambda: e4_failover(a, link))]
    for name, fn in steps:
        if name in a.skip:
            continue
        print("running", name, "...", flush=True)
        try:
            res[name] = fn()
            write_csv(a.out, name + ".csv", res[name])
        except Exception as e:                           # keep going: partial results beat none
            errors[name] = str(e)
            print("  FAILED:", e)
            try:
                call(a.base, "/api/impair", {"a": link[0], "b": link[1], "loss": 0, "delay": 0})
            except Exception:
                pass
    res["errors"] = errors
    with open(os.path.join(a.out, "results.json"), "w") as f:
        json.dump(res, f, indent=2)
    with open(os.path.join(a.out, "report.html"), "w") as f:
        f.write(build_report(res, a, link))
    print("Wrote %s/report.html, results.json and CSV files." % a.out)


if __name__ == "__main__":
    main()
