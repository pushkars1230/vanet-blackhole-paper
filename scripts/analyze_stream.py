#!/usr/bin/env python3
"""PDR, end-to-end delay, throughput, routing overhead and NRL from Stream-*.sca"""
import collections, math, statistics, sys

DURATION = 25.0   # s of traffic: numWarnings x sendInterval

def parse(path):
    attrs, sc = {}, collections.defaultdict(dict)
    for line in open(path, errors="ignore"):
        p = line.rstrip("\n").split(None, 3)
        if not p: continue
        if p[0] in ("attr", "itervar") and len(p) >= 3:
            attrs[p[1]] = " ".join(p[2:]).replace("\\", "").strip('"')
        elif p[0] == "scalar" and len(p) == 4:
            try: sc[p[1]][p[2]] = float(p[3])
            except ValueError: pass
    return attrs, sc

runs = []
for path in sys.argv[1:]:
    a, sc = parse(path)
    apps = [v for m, v in sc.items() if m.endswith(".app[0]")]
    aodvs = [v for m, v in sc.items() if m.endswith(".aodv")]
    udps = [v for m, v in sc.items() if m.endswith(".udp")]
    src = sc.get("Scenario.node[0].aodv", {})
    sent = sum(v.get("warningsSent", 0) for v in apps)
    recv = sum(v.get("warningsReceived", 0) for v in apps)
    acks = sum(v.get("acksSent", 0) for v in apps)
    runs.append({
        "f": float(a.get("bhFraction", "nan")), "det": a.get("detection", "?"),
        "valid": sent > 0, "sent": sent, "recv": recv,
        "delay": sum(v.get("e2eDelaySum", 0) for v in apps),
        "bytes": sum(v.get("bytesReceived", 0) for v in apps),
        "ro": sum(v.get("packetSent:count", 0) for v in udps) - sent - acks,
        "tp": src.get("detectionTruePositives", 0) + sum(v.get("plausibilityRejectsTP", 0) for v in aodvs),
        "fp": src.get("detectionFalsePositives", 0) + sum(v.get("plausibilityRejectsFP", 0) for v in aodvs),
    })

print(f"{len(runs)} runs, {sum(not r['valid'] for r in runs)} without a destination (excluded)\n")
g = collections.defaultdict(list)
for r in runs:
    if r["valid"]: g[(r["f"], r["det"])].append(r)
hdr = f"{'bhFrac':>6} {'detect':>12} {'n':>3} {'PDR %':>6} {'+-':>5} {'delay ms':>8} {'thr kbps':>8} {'RO':>7} {'NRL':>7} {'TP':>6} {'FP':>5}"
print(hdr); print("-" * len(hdr))
for k in sorted(g):
    v = g[k]; n = len(v)
    pdrs = [100 * r["recv"] / r["sent"] for r in v]
    ci = 1.96 * statistics.stdev(pdrs) / math.sqrt(n) if n > 1 else float("nan")
    recv = sum(r["recv"] for r in v)
    delay = 1000 * sum(r["delay"] for r in v) / recv if recv else float("nan")
    thr = statistics.mean(r["bytes"] * 8 / DURATION / 1000 for r in v)
    ro = statistics.mean(r["ro"] for r in v)
    nrl = sum(r["ro"] for r in v) / recv if recv else float("inf")
    print(f"{k[0]:>6.2f} {k[1]:>12} {n:>3} {statistics.mean(pdrs):>6.1f} {ci:>5.1f} {delay:>8.1f} {thr:>8.2f} "
          f"{ro:>7.0f} {nrl:>7.1f} {sum(r['tp'] for r in v):>6.0f} {sum(r['fp'] for r in v):>5.0f}")
