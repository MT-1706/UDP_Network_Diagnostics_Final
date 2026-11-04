#!/usr/bin/env python3
"""
Fixed-rate UDP probe used for the FAILOVER test.

A sender sends one probe every <interval> seconds for <duration> seconds WITHOUT waiting
for replies; a receiver thread records the replies.  Afterwards:
  * loss_pct           = probes with no reply / probes sent
  * longest_outage_ms  = longest run of consecutive lost probes x interval  (= service gap)
  * outage_start_s     = when (seconds after start) that longest gap began

usage: udp_stream_probe.py <dst-ip> [duration_s=10] [interval_s=0.02] [timeout_s=0.5]
Prints JSON, writes /tmp/stream_result.json.
"""
import json, socket, sys, threading, time

PORT = 9999


def run(dst, duration, interval, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)
    sent_at, rtt, errors = {}, {}, set()
    stop = threading.Event()

    def receiver():
        while not stop.is_set():
            try:
                data, _ = s.recvfrom(2048)
                seq = int(data.split(b"|")[0])
            except socket.timeout:
                continue
            except (ValueError, OSError):
                continue
            if seq in sent_at and seq not in rtt:
                rtt[seq] = (time.perf_counter() - sent_at[seq]) * 1000

    th = threading.Thread(target=receiver, daemon=True)
    th.start()
    n = max(1, int(duration / interval))
    start = time.perf_counter()
    for seq in range(n):
        target = start + seq * interval                   # fixed schedule, no drift
        delay = target - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
        sent_at[seq] = time.perf_counter()
        try:
            s.sendto(f"{seq}|{time.time()}".encode(), (dst, PORT))
        except OSError as e:
            errors.add(str(e))
    time.sleep(timeout)                                   # let the last replies arrive
    stop.set()
    th.join(1)

    lost = [q for q in range(n) if q not in rtt]
    best, cur, cur_start, best_start = 0, 0, 0, 0
    for q in range(n):                                    # longest consecutive loss run
        if q in rtt:
            cur = 0
        else:
            if cur == 0:
                cur_start = q
            cur += 1
            if cur > best:
                best, best_start = cur, cur_start
    rtts = list(rtt.values())
    return {
        "dst": dst, "sent": n, "received": len(rtts),
        "loss_pct": round(100 * len(lost) / n, 2),
        "longest_outage_ms": round(best * interval * 1000, 1),
        "outage_start_s": round(best_start * interval, 2) if best else None,
        "rtt_avg_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
        "errors": sorted(errors),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: udp_stream_probe.py <dst-ip> [duration_s] [interval_s] [timeout_s]")
    try:
        d = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
        i = float(sys.argv[3]) if len(sys.argv) > 3 else 0.02
        t = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
    except ValueError:
        sys.exit("duration, interval and timeout must be numbers")
    if d <= 0 or i <= 0 or t < 0:
        sys.exit("duration and interval must be > 0")
    res = run(sys.argv[1], d, i, t)
    print(json.dumps(res, indent=2))
    try:
        json.dump(res, open("/tmp/stream_result.json", "w"))
    except OSError:
        pass
