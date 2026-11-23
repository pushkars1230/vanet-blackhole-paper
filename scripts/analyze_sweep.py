#!/usr/bin/env python3
"""
analyze_sweep.py (v2) -- Sweep-*.sca -> results tables.

    python3 analyze_sweep.py results/Sweep-*.sca
    python3 analyze_sweep.py --csv sweep_runs.csv results/Sweep-*.sca

TP/FP: ackTimeout -> blacklist decisions at node[0];
       plausibility -> RREP rejections summed over all honest nodes.
"""
import argparse, collections, csv, math, statistics


def parse_sca(path):
    attrs, scalars = {}, collections.defaultdict(dict)
    with open(path, errors="ignore") as f:
        for line in f:
            parts = line.rstrip("\n").split(None, 3)
            if not parts:
                continue
            if parts[0] in ("attr", "itervar") and len(parts) >= 3:
                attrs[parts[1]] = " ".join(parts[2:]).replace("\\", "").strip('"')
            elif parts[0] == "scalar" and len(parts) == 4:
                try:
                    scalars[parts[1]][parts[2]] = float(parts[3])
                except ValueError:
                    pass
    return attrs, scalars


def run_record(path):
    attrs, sc = parse_sca(path)
    app = sc.get("Scenario.node[0].app[0]", {})
    src = sc.get("Scenario.node[0].aodv", {})
    aodvs = [v for m, v in sc.items() if m.endswith(".aodv")]
    delivered = any(v.get("warningsReceived", 0) > 0 for m, v in sc.items()
                    if m.endswith(".app[0]") and not m.startswith("Scenario.node[0]."))
    nbr = [v["maxNeighborDistance"] for v in aodvs if "maxNeighborDistance" in v]
    return {
        "file": path,
        "bhFraction": float(attrs.get("bhFraction", "nan")),
        "detection": attrs.get("detection", "?"),
        "maxRange": attrs.get("maxRange", ""),
        "repetition": int(attrs.get("repetition", -1)),
        "valid": "destDistance" in app,
        "destDistance": app.get("destDistance", float("nan")),
        "delivered": delivered,
        "acked": app.get("acksReceived", 0) > 0,
        "latency": app.get("ackLatency", float("nan")),
        "timeouts": int(app.get("ackTimeouts", 0)),
        "attackers": sum(1 for v in aodvs if v.get("isBlackhole", 0) == 1),
        "hit": any(v.get("blackholePacketsDropped", 0) > 0 for v in aodvs),
        "tp": int(src.get("detectionTruePositives", 0) + sum(v.get("plausibilityRejectsTP", 0) for v in aodvs)),
        "fp": int(src.get("detectionFalsePositives", 0) + sum(v.get("plausibilityRejectsFP", 0) for v in aodvs)),
        "maxNbrDist": max(nbr) if nbr else float("nan"),
    }


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))] if xs else float("nan")


ap = argparse.ArgumentParser()
ap.add_argument("files", nargs="+")
ap.add_argument("--csv")
args = ap.parse_args()
runs = [run_record(f) for f in args.files]
if args.csv:
    with open(args.csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(runs[0].keys())); w.writeheader(); w.writerows(runs)

print(f"{len(runs)} runs, {sum(not r['valid'] for r in runs)} invalid (no destination in band, excluded)\n")

d = [r["maxNbrDist"] for r in runs if not math.isnan(r["maxNbrDist"])]
if d:
    print(f"Largest one-hop distance per run [m]: median {statistics.median(d):.0f}, "
          f"p95 {pct(d, 0.95):.0f}, max {max(d):.0f}  (n={len(d)})\n")

groups = collections.defaultdict(list)
for r in runs:
    groups[(r["maxRange"], r["bhFraction"], r["detection"])].append(r)

hdr = (f"{'Rmax':>6} {'bhFrac':>6} {'detect':>12} {'n':>3} {'PDR':>5} {'95% CI':>13} "
       f"{'lat med[s]':>10} {'hit%':>5} {'atk':>5} {'TP':>5} {'FP':>5} {'FP/run':>6}")
print(hdr); print("-" * len(hdr))
for key in sorted(groups):
    g = [r for r in groups[key] if r["valid"]]; n = len(g)
    if n == 0:
        continue
    k = sum(r["delivered"] for r in g); lo, hi = wilson(k, n)
    lats = [r["latency"] for r in g if r["acked"] and not math.isnan(r["latency"])]
    lat = statistics.median(lats) if lats else float("nan")
    tp = sum(r["tp"] for r in g); fp = sum(r["fp"] for r in g)
    print(f"{key[0]:>6} {key[1]:>6.2f} {key[2]:>12} {n:>3} {k / n:>5.2f} [{lo:.2f},{hi:.2f}] {lat:>10.3f} "
          f"{100 * sum(r['hit'] for r in g) / n:>5.0f} {statistics.mean(r['attackers'] for r in g):>5.1f} "
          f"{tp:>5} {fp:>5} {fp / n:>6.2f}")

print("\nPaired with 'none' (same seed, same Rmax):")
print(f"{'Rmax':>6} {'bhFrac':>6} {'detect':>12} {'pairs':>5} {'rescued':>7} {'broken':>6} {'both ok':>7} {'both fail':>9}")
by = {(r["maxRange"], r["bhFraction"], r["repetition"], r["detection"]): r for r in runs if r["valid"]}
for (rm, f, det) in sorted({(r["maxRange"], r["bhFraction"], r["detection"]) for r in runs}):
    if det == "none":
        continue
    c = collections.Counter()
    for rep in sorted({r["repetition"] for r in runs}):
        a, b = by.get((rm, f, rep, "none")), by.get((rm, f, rep, det))
        if a is None or b is None:
            continue
        c["pairs"] += 1
        if not a["delivered"] and b["delivered"]: c["rescued"] += 1
        elif a["delivered"] and not b["delivered"]: c["broken"] += 1
        elif a["delivered"]: c["both ok"] += 1
        else: c["both fail"] += 1
    print(f"{rm:>6} {f:>6.2f} {det:>12} {c['pairs']:>5} {c['rescued']:>7} {c['broken']:>6} "
          f"{c['both ok']:>7} {c['both fail']:>9}")
