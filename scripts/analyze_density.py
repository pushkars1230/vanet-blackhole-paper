#!/usr/bin/env python3
import collections, math, statistics, sys

MODEL = {40: [0.57, 0.33, 0.19, 0.11], 120: [0.19, 0.04, 0.01, 0.00]}
FRACS = [0.05, 0.10, 0.15, 0.20]

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

def wilson(k, n, z=1.96):
    if n == 0: return (float("nan"), float("nan"))
    p = k / n; d = 1 + z*z/n; c = (p + z*z/(2*n)) / d
    h = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return (max(0.0, c-h), min(1.0, c+h))

runs = []
for path in sys.argv[1:]:
    a, sc = parse(path)
    app = sc.get("Scenario.node[0].app[0]", {}); src = sc.get("Scenario.node[0].aodv", {})
    aodvs = [v for m, v in sc.items() if m.endswith(".aodv")]
    runs.append({
        "N": int(a.get("N", -1)), "f": float(a.get("bhFraction", "nan")),
        "det": a.get("detection", "?"), "rep": int(a.get("repetition", -1)),
        "valid": "destDistance" in app,
        "ok": any(v.get("warningsReceived", 0) > 0 for m, v in sc.items()
                  if m.endswith(".app[0]") and not m.startswith("Scenario.node[0].")),
        "lat": app.get("ackLatency", float("nan")),
        "atk": sum(1 for v in aodvs if v.get("isBlackhole", 0) == 1),
        "tp": int(src.get("detectionTruePositives", 0) + sum(v.get("plausibilityRejectsTP", 0) for v in aodvs)),
        "fp": int(src.get("detectionFalsePositives", 0) + sum(v.get("plausibilityRejectsFP", 0) for v in aodvs)),
        "nbr": max([v["maxNeighborDistance"] for v in aodvs if "maxNeighborDistance" in v] or [float("nan")]),
    })

print(f"{len(runs)} runs")
g = collections.defaultdict(list)
for r in runs: g[(r["N"], r["f"], r["det"])].append(r)
base = {}
print(f"\n{'N':>4} {'bhFrac':>6} {'detect':>12} {'valid':>5} {'inval':>5} {'PDR':>5} {'95% CI':>13} {'lat med':>7} {'atk':>5} {'TP':>5} {'FP':>4} {'model':>6} {'PDR/base':>8}")
for k in sorted(g):
    allr = g[k]; v = [r for r in allr if r["valid"]]; n = len(v)
    if n == 0:
        print(f"{k[0]:>4} {k[1]:>6.2f} {k[2]:>12} {0:>5} {len(allr):>5}"); continue
    ok = sum(r["ok"] for r in v); lo, hi = wilson(ok, n); pdr = ok / n
    if k[1] == 0: base[(k[0], k[2])] = pdr
    lats = [r["lat"] for r in v if r["ok"] and not math.isnan(r["lat"])]
    lat = statistics.median(lats) if lats else float("nan")
    model = norm = ""
    if k[2] == "plausibility" and k[1] in FRACS and k[0] in MODEL:
        model = f"{MODEL[k[0]][FRACS.index(k[1])]:.2f}"
        b = base.get((k[0], "plausibility"), 0)
        norm = f"{pdr / b:.2f}" if b else ""
    print(f"{k[0]:>4} {k[1]:>6.2f} {k[2]:>12} {n:>5} {len(allr)-n:>5} {pdr:>5.2f} [{lo:.2f},{hi:.2f}] {lat:>7.3f} "
          f"{statistics.mean(r['atk'] for r in v):>5.1f} {sum(r['tp'] for r in v):>5} {sum(r['fp'] for r in v):>4} {model:>6} {norm:>8}")

print("\nPaired with 'none' (same seed):")
print(f"{'N':>4} {'bhFrac':>6} {'detect':>12} {'pairs':>5} {'rescued':>7} {'broken':>6}")
by = {(r["N"], r["f"], r["rep"], r["det"]): r for r in runs if r["valid"]}
for (N, f, det) in sorted({(r["N"], r["f"], r["det"]) for r in runs}):
    if det == "none": continue
    c = collections.Counter()
    for rep in range(30):
        a, b = by.get((N, f, rep, "none")), by.get((N, f, rep, det))
        if a is None or b is None: continue
        c["pairs"] += 1
        if not a["ok"] and b["ok"]: c["rescued"] += 1
        elif a["ok"] and not b["ok"]: c["broken"] += 1
    print(f"{N:>4} {f:>6.2f} {det:>12} {c['pairs']:>5} {c['rescued']:>7} {c['broken']:>6}")

for N in sorted({r["N"] for r in runs}):
    d = [r["nbr"] for r in runs if r["N"] == N and not math.isnan(r["nbr"])]
    if d: print(f"\nN={N}: largest one-hop distance max {max(d):.0f} m")
