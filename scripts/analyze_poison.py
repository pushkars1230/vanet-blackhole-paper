#!/usr/bin/env python3
"""
analyze_poison.py -- CoopPoisonGrid-*.sca / CoopPoisonHighway-*.sca -> poisoning table.

    python3 analyze_poison.py results/CoopPoisonGrid-*.sca results/CoopPoisonHighway-*.sca

Per (scenario, poison, cap): delivered runs, packet delivery, mean learned bound
of the other honest vehicles, the share of them whose bound ever exceeded
rangeAlertLevel (1000 m), the share that had exceeded it by the accident
(t = 30 s, among vehicles already observing by then), and the median / 90th
percentile delay from a vehicle's first range observation to exceeding it.
node[1] (the advertiser) is excluded from the bound statistics.
"""
import collections, math, statistics, sys

ACCIDENT = 30.0


def parse_sca(path):
    attrs, scalars, header = {}, collections.defaultdict(dict), True
    with open(path, errors="ignore") as f:
        for line in f:
            p = line.rstrip("\n").split(None, 3)
            if not p:
                continue
            if p[0] in ("scalar", "statistic", "vector", "histogram"):
                header = False
            if p[0] == "itervar" and len(p) >= 3:
                attrs[p[1]] = " ".join(p[2:]).replace("\\", "").strip('"')
            elif p[0] == "attr" and header and len(p) >= 3:
                attrs.setdefault(p[1], " ".join(p[2:]).replace("\\", "").strip('"'))
            elif p[0] == "scalar" and len(p) == 4:
                try:
                    scalars[p[1]][p[2]] = float(p[3])
                except ValueError:
                    pass
    return attrs, scalars


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else float("nan")


rows = collections.defaultdict(list)
for path in sys.argv[1:]:
    a, sc = parse_sca(path)
    app = sc.get("Scenario.node[0].app[0]", {})
    if "destDistance" not in app:
        continue
    rec = sum(v.get("warningsReceived", 0) for m, v in sc.items()
              if m.endswith(".app[0]") and not m.startswith("Scenario.node[0]."))
    hon = [v for m, v in sc.items() if m.endswith(".aodv") and not m.startswith("Scenario.node[1].")
           and v.get("isBlackhole", 0) == 0 and "rangeFirstObservationTime" in v]
    obs = [v for v in hon if v["rangeFirstObservationTime"] >= 0]
    alert = [v for v in obs if v.get("rangeAlertTime", -1) >= 0]
    by_acc = [v for v in obs if v["rangeFirstObservationTime"] <= ACCIDENT]
    alert_acc = [v for v in by_acc if 0 <= v.get("rangeAlertTime", -1) <= ACCIDENT]
    key = (a.get("configname", "").replace("CoopPoison", ""), a.get("poison", "0"), a.get("cap", "0"))
    rows[key].append(dict(
        delivered=rec > 0, rec=rec, sent=app.get("warningsSent", 0),
        bound=statistics.mean(v["rangeUsedMean"] for v in obs if "rangeUsedMean" in v) if any("rangeUsedMean" in v for v in obs) else float("nan"),
        share=len(alert) / len(obs) if obs else float("nan"),
        share_acc=len(alert_acc) / len(by_acc) if by_acc else float("nan"),
        delays=[v["rangeAlertTime"] - v["rangeFirstObservationTime"] for v in alert]))

hdr = (f"{'scenario':>8} {'poison':>6} {'cap':>4} {'n':>3} {'runs':>6} {'pktPDR':>6} {'bound':>7} "
       f"{'>1000m':>7} {'by t=30':>7} {'med delay':>9} {'p90 delay':>9}")
print(hdr); print("-" * len(hdr))
for k in sorted(rows):
    g = rows[k]; n = len(g); d = sum(r["delivered"] for r in g)
    sent = sum(r["sent"] for r in g); pk = sum(r["rec"] for r in g) / sent if sent else float("nan")
    mean = lambda f: statistics.mean([r[f] for r in g if not math.isnan(r[f])]) if any(not math.isnan(r[f]) for r in g) else float("nan")
    delays = [x for r in g for x in r["delays"]]
    print(f"{k[0]:>8} {k[1]:>6} {k[2]:>4} {n:>3} {d:>3}/{n:<2} {pk:>6.3f} {mean('bound'):>7.0f} "
          f"{mean('share'):>7.2f} {mean('share_acc'):>7.2f} {pct(delays, 0.5):>8.1f}s {pct(delays, 0.9):>8.1f}s")
