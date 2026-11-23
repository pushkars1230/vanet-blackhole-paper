#!/usr/bin/env python3
"""
analyze_adaptive.py -- Adaptive-*.sca -> results tables for the adaptive R_max study.

    python3 analyze_adaptive.py results/Adaptive-*.sca
    python3 analyze_adaptive.py --csv adaptive_runs.csv results/Adaptive-*.sca

Groups runs by (power, bhFraction, variant). Variants:
  none       plain AODV
  fixed      plausibility, R_max fixed at 330 m (set for 20 mW)
  oracle     plausibility, R_max = true range for that power (reference)
  adaptiveX  plausibility, R_max learned per vehicle, margin X %
TP/FP = RREP rejections at honest vehicles (FP = honest reply rejected).
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


def variant_of(attrs):
    det = attrs.get("det", attrs.get("detection", "?"))
    rm = attrs.get("rm", "fixed")
    if det == "none":
        return "none"
    if rm in ("adaptive", "cooperative"):
        tag = "adaptive" if rm == "adaptive" else "coop"
        return f"{tag}{int(round(100 * float(attrs.get('margin', 0))))}"
    return rm            # "fixed" or "oracle"


def scenario_of(attrs):
    p = attrs.get("power", "20mW")
    if attrs.get("configname", "").startswith("Highway"):
        p = "hwy" + p
    if "sigma" in attrs:
        p = f"{p},err={attrs['sigma']},beacon={attrs['beacon']}"
    if "m" in attrs:
        p = f"{p},m={attrs['m']}"
    return p


def run_record(path):
    attrs, sc = parse_sca(path)
    app = sc.get("Scenario.node[0].app[0]", {})
    aodvs = [v for m, v in sc.items() if m.endswith(".aodv")]
    delivered = any(v.get("warningsReceived", 0) > 0 for m, v in sc.items()
                    if m.endswith(".app[0]") and not m.startswith("Scenario.node[0]."))
    nbr = [v["maxNeighborDistance"] for v in aodvs if "maxNeighborDistance" in v]
    used = [v["rangeUsedMean"] for v in aodvs if "rangeUsedMean" in v]
    return {
        "file": path,
        "power": scenario_of(attrs),
        "bhFraction": float(attrs.get("bhFraction", "nan")),
        "variant": variant_of(attrs),
        "repetition": int(attrs.get("repetition", -1)),
        "valid": "destDistance" in app,
        "delivered": delivered,
        "attackers": sum(1 for v in aodvs if v.get("isBlackhole", 0) == 1),
        "sent": app.get("warningsSent", 0),
        "received": sum(v.get("warningsReceived", 0) for m, v in sc.items()
                        if m.endswith(".app[0]") and not m.startswith("Scenario.node[0].")),
        "tp": int(sum(v.get("plausibilityRejectsTP", 0) for v in aodvs)),
        "fp": int(sum(v.get("plausibilityRejectsFP", 0) for v in aodvs)),
        "passedFakes": int(sum(v.get("plausibilityPassedFakes", 0) for v in aodvs)),
        "noEstimate": int(sum(v.get("rangeNoEstimate", 0) for v in aodvs)),
        "estimates": int(sum(v.get("rangeEstimates", 0) for v in aodvs)),
        "rangeUsedMean": statistics.mean(used) if used else float("nan"),
        "rangeUsedMin": min((v["rangeUsedMin"] for v in aodvs if "rangeUsedMin" in v), default=float("nan")),
        "maxNbrDist": max(nbr) if nbr else float("nan"),
    }


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def power_key(p):
    import re
    m = re.search(r"([0-9.]+)mW", p)
    return (p.startswith("hwy"), float(m.group(1)) if m else 0.0, p)


ORDER = {"none": 0, "fixed": 1, "oracle": 2}  # "oracle" = link-budget bound
def variant_key(v):
    return (ORDER.get(v, 3), v)


ap = argparse.ArgumentParser()
ap.add_argument("files", nargs="+")
ap.add_argument("--csv")
args = ap.parse_args()
runs = [run_record(f) for f in args.files]
if args.csv:
    with open(args.csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(runs[0].keys())); w.writeheader(); w.writerows(runs)

print(f"{len(runs)} runs, {sum(not r['valid'] for r in runs)} invalid (no destination in band, excluded)\n")

print("Measured largest one-hop distance per power [m] (the true range):")
for p in sorted({r["power"] for r in runs}, key=power_key):
    d = [r["maxNbrDist"] for r in runs if r["power"] == p and not math.isnan(r["maxNbrDist"])]
    if d:
        print(f"  {p:>14}: median {statistics.median(d):.0f}, max {max(d):.0f}  (n={len(d)})")
print()

groups = collections.defaultdict(list)
for r in runs:
    if r["valid"]:
        groups[(r["power"], r["bhFraction"], r["variant"])].append(r)

hdr = (f"{'scenario':>14} {'bhFrac':>6} {'variant':>11} {'n':>3} {'PDR':>5} {'95% CI':>13} "
       f"{'pktPDR':>6} {'TP':>6} {'FP':>5} {'FP/run':>6} {'passed':>6} {'R used':>7} {'R min':>6} {'noEst':>6}")
print(hdr); print("-" * len(hdr))
for key in sorted(groups, key=lambda k: (power_key(k[0]), k[1], variant_key(k[2]))):
    g = groups[key]; n = len(g)
    k = sum(r["delivered"] for r in g); lo, hi = wilson(k, n)
    tp = sum(r["tp"] for r in g); fp = sum(r["fp"] for r in g)
    ru = [r["rangeUsedMean"] for r in g if not math.isnan(r["rangeUsedMean"])]
    rm = [r["rangeUsedMin"] for r in g if not math.isnan(r["rangeUsedMin"])]
    sent = sum(r["sent"] for r in g); rec = sum(r["received"] for r in g)
    pk = rec / sent if sent else float("nan")
    print(f"{key[0]:>14} {key[1]:>6.2f} {key[2]:>11} {n:>3} {k / n:>5.2f} [{lo:.2f},{hi:.2f}] "
          f"{pk:>6.3f} {tp:>6} {fp:>5} {fp / n:>6.2f} {sum(r['passedFakes'] for r in g):>6} "
          f"{(statistics.mean(ru) if ru else float('nan')):>7.0f} {(min(rm) if rm else float('nan')):>6.0f} "
          f"{sum(r['noEstimate'] for r in g):>6}")

print("\nPaired with 'none' (same seed, same power, same attacker share):")
print(f"{'scenario':>14} {'bhFrac':>6} {'variant':>11} {'pairs':>5} {'rescued':>7} {'broken':>6} {'both ok':>7} {'both fail':>9}")
by = {(r["power"], r["bhFraction"], r["repetition"], r["variant"]): r for r in runs if r["valid"]}
for (p, f, v) in sorted({(r["power"], r["bhFraction"], r["variant"]) for r in runs},
                        key=lambda k: (power_key(k[0]), k[1], variant_key(k[2]))):
    if v == "none":
        continue
    c = collections.Counter()
    for rep in sorted({r["repetition"] for r in runs}):
        a, b = by.get((p, f, rep, "none")), by.get((p, f, rep, v))
        if a is None or b is None:
            continue
        c["pairs"] += 1
        if not a["delivered"] and b["delivered"]: c["rescued"] += 1
        elif a["delivered"] and not b["delivered"]: c["broken"] += 1
        elif a["delivered"]: c["both ok"] += 1
        else: c["both fail"] += 1
    print(f"{p:>14} {f:>6.2f} {v:>11} {c['pairs']:>5} {c['rescued']:>7} {c['broken']:>6} "
          f"{c['both ok']:>7} {c['both fail']:>9}")
