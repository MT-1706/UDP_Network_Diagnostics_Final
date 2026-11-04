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

# Import libraries for API requests, CSV/HTML generation, statistics and command-line arguments.
import argparse, csv, html, json, os, statistics, sys, time, urllib.request


# Sends an HTTP request to the dashboard API and returns its JSON response.
def call(base, path, body=None, timeout=180):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)  # Convert the JSON response into a Python object.
    except urllib.error.HTTPError as e:
        try:
            msg = json.load(e).get("error", e.reason)  # Extract the dashboard's error message.
        except Exception:
            msg = e.reason
        raise RuntimeError("%s -> %s" % (path, msg))


# Writes experiment results into a CSV file.
def write_csv(out, name, rows):
    if not rows:
        return  # Avoid creating an empty CSV file.
    with open(os.path.join(out, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))  # Use dictionary keys as column names.
        w.writeheader()
        w.writerows(rows)  # Write all experiment records.


# ------------------------------------------------------------------ experiments

# E1: Compare the available paths using hop count and measured RTT.
def e1_paths(a):
    r = call(a.base, "/api/measure", {"dst": a.dst, "count": a.count})
    # Extract the important metrics for each measured path.
    rows = [{"path": " > ".join(p["names"]), "hops": p["hops"], "expected_rtt_ms": p["est_rtt_ms"],
             "measured_rtt_ms": p.get("measured_rtt_ms"), "jitter_ms": p.get("jitter_ms"),
             "loss_pct": p.get("loss_pct")} for p in r["paths"]]
    return rows, r


# E2: Inject packet loss and compare expected loss with actual measured loss.
def e2_loss(a, link):
    rows = []
    for p in a.loss_levels:
        # Apply the selected packet-loss percentage to the chosen link.
        call(a.base, "/api/impair", {"a": link[0], "b": link[1], "loss": p, "delay": 0})
        time.sleep(0.5)  # Allow the network impairment to take effect.
        d = call(a.base, "/api/diagnose", {"dst": a.dst, "count": a.count * 2})

        # one-way loss p applies to each direction -> round trip survives with (1-p)^2
        # Calculate expected round-trip loss when packets can be lost in both directions.
        exp = round(100 * (1 - (1 - p / 100) ** 2), 2)
        rows.append({"injected_loss_pct_per_direction": p, "expected_rtt_loss_pct": exp,
                     "measured_loss_pct": d["probe"]["loss_pct"], "probes": d["probe"]["sent"],
                     "status": d["status"]})

    # Remove the impairment and restore normal link conditions.
    call(a.base, "/api/impair", {"a": link[0], "b": link[1], "loss": 0, "delay": 0})
    return rows


# E3: Inject additional delay and observe its effect on round-trip time.
def e3_delay(a, link):
    rows = []
    for extra in a.delay_levels:
        # Apply extra delay to the selected link.
        call(a.base, "/api/impair", {"a": link[0], "b": link[1], "loss": 0, "delay": extra})
        time.sleep(0.5)
        d = call(a.base, "/api/diagnose", {"dst": a.dst, "count": a.count})

        # Use the first measurement as the baseline RTT.
        base = rows[0]["measured_rtt_ms"] if rows else d["probe"]["rtt_avg_ms"]
        rows.append({"extra_delay_ms_per_direction": extra,
                     # Round-trip delay increases in both directions.
                     "expected_rtt_ms": None if base is None else round(base + 2 * extra, 2),
                     "measured_rtt_ms": d["probe"]["rtt_avg_ms"], "jitter_ms": d["probe"]["jitter_ms"]})

    # Restore the link to normal conditions after testing.
    call(a.base, "/api/impair", {"a": link[0], "b": link[1], "loss": 0, "delay": 0})
    return rows


# E4: Test network recovery by repeatedly failing and restoring a link.
def e4_failover(a, link):
    rows = []
    for i in range(a.trials):
        # Fail the link at 3 seconds and restore it at 7 seconds.
        r = call(a.base, "/api/failover", {"dst": a.dst, "link": list(link), "duration": 10,
                                           "fail_at": 3, "restore_at": 7})
        rows.append({"trial": i + 1, "outage_ms": r["longest_outage_ms"], "loss_pct": r["loss_pct"],
                     "controller_detect_ms": r["controller_detect_ms"],
                     "controller_reroute_ms": r["controller_reroute_ms"],
                     "path_after": " > ".join(r["path_after"] or [])})
        time.sleep(3)  # let LLDP rediscover the restored link
    return rows


# ------------------------------------------------------------------ report (inline SVG)

# Colours used to distinguish the different chart series.
COLORS = ["#2a6fdb", "#e8833a", "#2f9e6b", "#8e5bd9"]


# Generates a bar chart using SVG directly, without external plotting libraries.
def bar_chart(title, cats, series, ylabel):
    """series = {name: [values]} ; None values drawn as gaps."""
    W, H, L, B, T = 640, 300, 56, 56, 34  # Chart dimensions and margins.

    # Find the largest available value to scale the chart.
    vals = [v for s in series.values() for v in s if v is not None]
    top = max(vals) * 1.15 if vals and max(vals) > 0 else 1

    pw, ph = W - L - 12, H - T - B  # Usable plot width and height.
    grp = pw / max(1, len(cats))  # Width allocated to each category.
    bw = grp * 0.7 / max(1, len(series))  # Width of each individual bar.

    # Start building the SVG chart and add its title.
    o = ['<svg viewBox="0 0 %d %d" role="img" aria-label="%s" class="chart">' % (W, H, html.escape(title)),
         '<text x="%d" y="20" class="ct">%s</text>' % (L, html.escape(title))]

    # Draw five horizontal grid lines and their numerical labels.
    for i in range(5):
        y = T + ph - ph * i / 4
        o.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" class="grid"/>' % (L, W - 12, y, y))
        o.append('<text x="%d" y="%.1f" class="ax" text-anchor="end">%.3g</text>' % (L - 6, y + 4, top * i / 4))

    # Add the vertical axis label.
    o.append('<text x="14" y="%d" class="ax" transform="rotate(-90 14 %d)" text-anchor="middle">%s</text>'
             % (T + ph / 2, T + ph / 2, html.escape(ylabel)))

    # Draw bars for every category and every data series.
    for ci, c in enumerate(cats):
        gx = L + ci * grp + grp * 0.15
        for si, (name, vs) in enumerate(series.items()):
            v = vs[ci]
            if v is None:
                continue  # Skip missing measurements.

            h = ph * v / top  # Convert the value into bar height.
            x = gx + si * bw
            o.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s"><title>%s: %s = %s</title></rect>'
                     % (x, T + ph - h, bw - 2, h, COLORS[si % 4], html.escape(str(c)), html.escape(name), v))
            # Display the numerical value above the bar.
            o.append('<text x="%.1f" y="%.1f" class="ax" text-anchor="middle">%.3g</text>'
                     % (x + bw / 2, T + ph - h - 4, v))

        # Display the category name below the bars.
        o.append('<text x="%.1f" y="%d" class="ax" text-anchor="middle">%s</text>'
                 % (L + ci * grp + grp / 2, H - B + 18, html.escape(str(c))))

    # Draw the legend to identify each data series.
    for si, name in enumerate(series):
        o.append('<rect x="%d" y="%d" width="10" height="10" fill="%s"/><text x="%d" y="%d" class="ax">%s</text>'
                 % (L + si * 150, H - 16, COLORS[si % 4], L + si * 150 + 14, H - 7, html.escape(name)))

    o.append("</svg>")
    return "".join(o)  # Combine all SVG elements into one chart string.


# Converts experiment data into an HTML table.
def table(rows):
    if not rows:
        return "<p>no data</p>"

    # Generate table headings from the dictionary keys.
    h = "".join("<th>%s</th>" % html.escape(k) for k in rows[0])

    # Generate table cells from each result dictionary.
    b = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % html.escape("" if v is None else str(v))
                                        for v in r.values()) for r in rows)
    return "<table><tr>%s</tr>%s</table>" % (h, b)


# Builds the final HTML report containing experiment results and charts.
def build_report(res, a, link):
    parts = ["<h1>Performance evaluation</h1><p>Destination %s &middot; impaired link %s &middot; %s</p>"
             % (a.dst, "-".join(link), time.strftime("%Y-%m-%d %H:%M"))]

    # E1 report: compare expected and measured RTT for different paths.
    if res.get("e1"):
        r = res["e1"]
        parts.append("<h2>E1 - Path comparison (hops vs measured latency)</h2>")
        parts.append(bar_chart("RTT per path", [x["path"] for x in r],
                               {"expected (config)": [x["expected_rtt_ms"] for x in r],
                                "measured": [x["measured_rtt_ms"] for x in r]}, "RTT (ms)"))
        parts.append(table(r))

        # Identify the path with the fewest hops and the lowest measured RTT.
        ok = [x for x in r if x["measured_rtt_ms"] is not None]
        if ok:
            fewest = min(r, key=lambda x: x["hops"])
            best = min(ok, key=lambda x: x["measured_rtt_ms"])
            parts.append("<p><b>Finding:</b> fewest-hop path = %s (%s ms); lowest-latency path = %s (%s ms). %s</p>" % (
                fewest["path"], fewest["measured_rtt_ms"], best["path"], best["measured_rtt_ms"],
                "They differ - hop count alone is a poor metric." if fewest is not best else "They coincide."))

    # E2 report: compare expected packet loss with measured packet loss.
    if res.get("e2"):
        r = res["e2"]
        parts.append("<h2>E2 - Packet-loss injection</h2>")
        parts.append(bar_chart("Round-trip loss vs injected loss", [str(x["injected_loss_pct_per_direction"]) + " %" for x in r],
                               {"expected": [x["expected_rtt_loss_pct"] for x in r],
                                "measured": [x["measured_loss_pct"] for x in r]}, "loss (%)"))
        parts.append(table(r))

    # E3 report: compare expected RTT with measured RTT under added delay.
    if res.get("e3"):
        r = res["e3"]
        parts.append("<h2>E3 - Delay injection</h2>")
        parts.append(bar_chart("RTT vs injected delay", ["+%s ms" % x["extra_delay_ms_per_direction"] for x in r],
                               {"expected": [x["expected_rtt_ms"] for x in r],
                                "measured": [x["measured_rtt_ms"] for x in r]}, "RTT (ms)"))
        parts.append(table(r))

    # E4 report: show service outage and controller recovery timings.
    if res.get("e4"):
        r = res["e4"]
        parts.append("<h2>E4 - Link-failure recovery</h2>")
        parts.append(bar_chart("Recovery per trial", ["trial %d" % x["trial"] for x in r],
                               {"service outage": [x["outage_ms"] for x in r],
                                "controller detect": [x["controller_detect_ms"] for x in r],
                                "flows reprogrammed": [x["controller_reroute_ms"] for x in r]}, "ms"))
        parts.append(table(r))

        # Calculate average, minimum and maximum outage across valid trials.
        outs = [x["outage_ms"] for x in r if x["outage_ms"] is not None]
        if outs:
            parts.append("<p><b>Mean outage:</b> %.0f ms (min %.0f, max %.0f) over %d trials.</p>"
                         % (statistics.mean(outs), min(outs), max(outs), len(outs)))

    # Include any experiment errors in the report.
    if res.get("errors"):
        parts.append("<h2>Experiments that failed</h2><ul>%s</ul>" %
                     "".join("<li>%s: %s</li>" % (html.escape(k), html.escape(v)) for k, v in res["errors"].items()))

    # CSS controls the report layout, table formatting and chart appearance.
    css = ("body{font:15px system-ui;max-width:720px;margin:2rem auto;padding:0 16px;background:#fff;color:#1b1f24}"
           "table{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:13px}td,th{border:1px solid #ccd;padding:4px 8px;text-align:left}"
           ".chart{width:100%;height:auto}.grid{stroke:#d5d9df}.ax{font-size:11px;fill:#555}.ct{font-weight:600;font-size:14px;fill:#1b1f24}"
           "@media (prefers-color-scheme:dark){body{background:#14171c;color:#e6e8eb}td,th{border-color:#3a414b}.grid{stroke:#333a44}.ax{fill:#aab}.ct{fill:#e6e8eb}}")
    return "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Performance report</title><style>%s</style>%s" % (css, "".join(parts))


# Main function: reads arguments, runs selected experiments and saves the results.
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)

    # Command-line options for the destination, dashboard, link and experiment settings.
    ap.add_argument("--dst", required=True)
    ap.add_argument("--base", default="http://127.0.0.1:5000")
    ap.add_argument("--link", help="link to impair / fail, e.g. s1-s3 (default: first link of the active path)")
    ap.add_argument("--count", type=int, default=40)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--loss-levels", type=float, nargs="+", default=[0, 5, 10, 20], dest="loss_levels")
    ap.add_argument("--delay-levels", type=float, nargs="+", default=[0, 10, 20, 40], dest="delay_levels")
    ap.add_argument("--out", default="results")
    ap.add_argument("--skip", nargs="*", default=[], choices=["e1", "e2", "e3", "e4"])
    a = ap.parse_args()  # Parse the arguments supplied by the user.
    os.makedirs(a.out, exist_ok=True)  # Create the output directory if it does not exist.

    # Check whether the dashboard is reachable before starting experiments.
    try:
        d = call(a.base, "/api/diagnose", {"dst": a.dst, "count": 5})
    except Exception as e:
        sys.exit("Cannot reach the dashboard / run a probe: %s" % e)

    # Use the provided link, or select the first link from the active path.
    if a.link:
        link = a.link.split("-")
    elif d.get("primary") and len(d["primary"]) > 1:
        link = d["primary"][:2]
    else:
        sys.exit("No inter-switch link on the active path; pass --link (e.g. s1-s3)")

    # Validate that the link contains exactly two switch names.
    if len(link) != 2:
        sys.exit("--link must look like s1-s3")
    print("Active path:", " > ".join(d["primary"] or ["?"]), "| experiment link:", "-".join(link))

    res, errors = {}, {}  # Store successful results and experiment errors separately.

    # Map each experiment name to the function that runs it.
    steps = [("e1", lambda: e1_paths(a)[0]), ("e2", lambda: e2_loss(a, link)),
             ("e3", lambda: e3_delay(a, link)), ("e4", lambda: e4_failover(a, link))]

    for name, fn in steps:
        if name in a.skip:
            continue  # Skip experiments selected by the user.

        print("running", name, "...", flush=True)
        try:
            res[name] = fn()  # Run the experiment and store its results.
            write_csv(a.out, name + ".csv", res[name])  # Save that experiment's CSV.
        except Exception as e:                           # keep going: partial results beat none
            errors[name] = str(e)
            print("  FAILED:", e)

            # Try to remove any remaining network impairment after a failure.
            try:
                call(a.base, "/api/impair", {"a": link[0], "b": link[1], "loss": 0, "delay": 0})
            except Exception:
                pass  # Continue even if cleanup also fails.

    res["errors"] = errors

    # Save all experiment results together in JSON format.
    with open(os.path.join(a.out, "results.json"), "w") as f:
        json.dump(res, f, indent=2)

    # Generate and save the final HTML report.
    with open(os.path.join(a.out, "report.html"), "w") as f:
        f.write(build_report(res, a, link))

    print("Wrote %s/report.html, results.json and CSV files." % a.out)


if __name__ == "__main__":
    main()  # Start the performance evaluation.