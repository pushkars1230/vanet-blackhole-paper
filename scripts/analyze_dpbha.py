#!/usr/bin/env python3
"""
analyze_dpbha.py -- DpbhaGrid-*.sca / DpbhaHighway-*.sca -> one summary table.

    python3 analyze_dpbha.py results/DpbhaGrid-*.sca results/DpbhaHighway-*.sca

Variants: none | dpbha | fixed (geometric, 330 m) | cooperative | dpbha+fixed
Columns: delivered runs (Wilson 95 % CI), packet delivery, geometric rejections
(TP/FP), DPBHA grey-list TP/FP, blacklisted attackers (TP/FP), baits sent,
share of DPBHA windows with a single reply (where lambda cannot flag anything).
Grey/black counts are summed over deciding vehicles: an attacker caught by two
sources counts twice.
"""
import collections, math, sys


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


def variant(a):
    det, rm = a.get("detection", a.get("det", "?")), a.get("rm", "fixed")
    if a.get("dpbha", "false") == "true":
        v = "dpbha" if det == "none" else "dpbha+fixed"
        if "win" in a and not (a["win"] == "0.1" and a.get("alarm", "false") == "false"):
            v += f"-w{a['win']}" + ("-alarm" if a.get("alarm") == "true" else "")
        return v
    if det == "none":
        return "none"
    return "fixed" if rm == "fixed" else rm


def wilson(k, n, z=1.96):
    if n == 0:
        return float("nan"), float("nan")
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


rows = collections.defaultdict(list)
for path in sys.argv[1:]:
    a, sc = parse_sca(path)
    app = sc.get("Scenario.node[0].app[0]", {})
    if "destDistance" not in app:
        continue
    aodv = [v for m, v in sc.items() if m.endswith(".aodv")]
    rec = sum(v.get("warningsReceived", 0) for m, v in sc.items()
              if m.endswith(".app[0]") and not m.startswith("Scenario.node[0]."))
    s = lambda k: sum(v.get(k, 0) for v in aodv)
    cfg = a.get("configname", "").replace("DpbhaSens", "Dpbha")
    key = (cfg, float(a.get("bhFraction", "nan")), a.get("jump", "-"), variant(a))
    rows[key].append(dict(delivered=rec > 0, rec=rec, sent=app.get("warningsSent", 0),
                          gtp=s("plausibilityRejectsTP"), gfp=s("plausibilityRejectsFP"),
                          dgt=s("dpbhaGreyTP"), dgf=s("dpbhaGreyFP"), dbt=s("dpbhaBlackTP"), dbf=s("dpbhaBlackFP"),
                          baits=s("dpbhaBaitsSent"), adrop=s("dpbhaAlarmDrops"), win=s("dpbhaWindows"), single=s("dpbhaSingleReplyWindows")))

ORDER = {"none": 0, "dpbha": 1, "fixed": 2, "cooperative": 3, "dpbha+fixed": 4}   # sensitivity variants sort after
hdr = (f"{'config':>12} {'bh':>4} {'jump':>5} {'variant':>18} {'n':>3} {'PDR':>5} {'95% CI':>13} {'pktPDR':>6} "
       f"{'geoTP':>6} {'geoFP':>5} {'greyTP':>6} {'greyFP':>6} {'blkTP':>5} {'blkFP':>5} {'baits':>5} {'1-reply':>7} {'alarmDrop':>9}")
print(hdr); print("-" * len(hdr))
for k in sorted(rows, key=lambda k: (k[0], k[1], k[2], ORDER.get(k[3], 9))):
    g = rows[k]; n = len(g); d = sum(r["delivered"] for r in g); lo, hi = wilson(d, n)
    sent = sum(r["sent"] for r in g); pk = sum(r["rec"] for r in g) / sent if sent else float("nan")
    t = lambda f: int(sum(r[f] for r in g))
    win = t("win"); single = f"{t('single') / win:.2f}" if win else "-"
    print(f"{k[0]:>12} {k[1]:>4.2f} {k[2]:>5} {k[3]:>18} {n:>3} {d / n:>5.2f} [{lo:.2f},{hi:.2f}] {pk:>6.3f} "
          f"{t('gtp'):>6} {t('gfp'):>5} {t('dgt'):>6} {t('dgf'):>6} {t('dbt'):>5} {t('dbf'):>5} {t('baits'):>5} {single:>7} {t('adrop'):>9}")
