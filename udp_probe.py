import socket, time, json, sys, statistics

if len(sys.argv) < 2:
    sys.exit("usage: udp_probe.py <dst-ip> [count] [interval_s] [timeout_s]")
dst   = sys.argv[1]
try:
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    interval = float(sys.argv[3]) if len(sys.argv) > 3 else 0.1   # optional: gap between probes
    timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 1.0    # optional: wait for a reply
except ValueError:
    sys.exit("count must be an integer; interval and timeout must be numbers")
if count < 1 or interval < 0 or timeout <= 0:
    sys.exit("count >= 1, interval >= 0, timeout > 0 required")
port = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(timeout)

rtts, lost, errors = [], [], []
for seq in range(count):
    t0 = time.perf_counter()
    try:
        s.sendto(f"{seq}|{time.time()}".encode(), (dst, port))
    except OSError as e:          # e.g. network unreachable: count as lost
        lost.append(seq)
        errors.append(str(e))
        time.sleep(interval)
        continue
    try:
        while True:
            data, _ = s.recvfrom(2048)
            try:
                if int(data.split(b"|")[0]) == seq:
                    break
            except ValueError:    # ignore malformed / stray packets
                continue
            # stale reply from an earlier probe: keep waiting
        rtts.append((time.perf_counter() - t0) * 1000)
    except socket.timeout:
        lost.append(seq)
    except OSError as e:          # e.g. ICMP error surfaced by the OS
        lost.append(seq)
        errors.append(str(e))
    time.sleep(interval)

jitter = (statistics.mean(abs(a - b) for a, b in zip(rtts, rtts[1:]))
          if len(rtts) > 1 else 0)
result = {
    "dst": dst, "sent": count, "received": len(rtts),
    "loss_pct": round(100 * len(lost) / count, 2),
    "rtt_min_ms": round(min(rtts), 2) if rtts else None,
    "rtt_avg_ms": round(statistics.mean(rtts), 2) if rtts else None,
    "rtt_max_ms": round(max(rtts), 2) if rtts else None,
    "jitter_ms": round(jitter, 2),
    "lost_seq": lost,
    "errors": sorted(set(errors)),
}
print(json.dumps(result, indent=2))
try:
    with open("/tmp/probe_result.json", "w") as f:       # for analyzer.py; failing to save must not break the probe
        json.dump(result, f)
except OSError:
    pass
