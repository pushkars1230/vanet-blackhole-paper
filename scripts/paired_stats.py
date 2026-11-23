#!/usr/bin/env python3
"""
paired_stats.py -- paired significance tests and effect sizes for any sweep.

    python3 paired_stats.py results/Sweep-*.sca
    python3 paired_stats.py results/Adaptive-*.sca results/Coop-*.sca
    python3 paired_stats.py results/Stream-*.sca

Runs are paired by seed (repetition) within each group of identical settings.
For every variant it reports, against no defence and against the fixed-bound
check (where present):
  delivery   k/n, Wilson 95 % CI, risk difference with Newcombe 95 % CI,
             exact two-sided McNemar test on discordant pairs (b = rescued, c = broken)
  packets    (stream runs only) mean paired difference in packet delivery ratio
             with 95 % t-interval, Wilcoxon signed-rank test (normal approximation)
"""
import collections, math, statistics, sys


def parse_sca(path):
    """Run-level attributes and iteration variables only (statistics also carry
    'attr' lines, which must not leak into the run description)."""
    attrs, scalars = {}, collections.defaultdict(dict)
    in_run_header = True
    with open(path, errors="ignore") as f:
        for line in f:
            parts = line.rstrip("\n").split(None, 3)
            if not parts:
                continue
            if parts[0] in ("scalar", "statistic", "vector", "histogram"):
                in_run_header = False
            if parts[0] == "itervar" and len(parts) >= 3:
                attrs[parts[1]] = " ".join(parts[2:]).replace("\\", "").strip('"')
            elif parts[0] == "attr" and in_run_header and len(parts) >= 3:
                attrs.setdefault(parts[1], " ".join(parts[2:]).replace("\\", "").strip('"'))
            elif parts[0] == "scalar" and len(parts) == 4:
                try:
                    scalars[parts[1]][parts[2]] = float(parts[3])
                except ValueError:
                    pass
    return attrs, scalars


VARIANT_KEYS = ("detection", "det", "rm", "margin", "dpbha", "win", "alarm", "poison", "cap")
SKIP_KEYS = VARIANT_KEYS + ("repetition", "runnumber", "seedset", "datetime", "datetimef", "processid",
                            "inifile", "iterationvars", "iterationvarsf", "iterationvarsd", "measurement",
                            "replication", "runid", "description", "network", "experiment", "oracle")


def variant(a):
    det = a.get("det", a.get("detection", "?"))
    rm = a.get("rm", "fixed")
    if a.get("dpbha", "false") == "true":          # DPBHA baseline, alone or with the fixed check
        v = "dpbha" if det == "none" else "dpbha+fixed"
        if "win" in a and not (a["win"] == "0.1" and a.get("alarm", "false") == "false"):
            v += f"-w{a['win']}" + ("-alarm" if a.get("alarm") == "true" else "")
        return v
    if a.get("poison", "0") not in ("0", ""):      # cooperative bound with one vehicle advertising an inflated range
        return f"{rm}{int(round(100 * float(a.get('margin', 0))))}-poison{a['poison']}" + \
               (f"-cap{a['cap']}" if a.get("cap", "0") not in ("0", "") else "")
    if det in ("none", "ackTimeout"):
        return det
    if rm == "fixed":
        return "fixed"
    if rm == "oracle":
        return "linkbudget"
    return f"{rm}{int(round(100 * float(a.get('margin', 0))))}"


def record(path):
    a, sc = parse_sca(path)
    app = sc.get("Scenario.node[0].app[0]", {})
    if "destDistance" not in app:
        return None
    recv = sum(v.get("warningsReceived", 0) for m, v in sc.items()
               if m.endswith(".app[0]") and not m.startswith("Scenario.node[0]."))
    sent = app.get("warningsSent", 0)
    itervars = ("bhFraction", "power", "maxRange", "N", "sigma", "beacon", "m", "jump")
    cfg = a.get("configname", "")
    family = "Adaptive+Coop" if cfg in ("Adaptive", "Coop") else cfg   # same seeds and settings, compared together
    for pre in ("DpbhaSens", "CoopPoison"):                              # v7 configs pair with the DPBHA runs
        if cfg.startswith(pre):
            family = "Dpbha" + cfg[len(pre):]
    group = (("configname", family),) + tuple((k, a[k]) for k in itervars if k in a)
    return {"group": group, "variant": variant(a), "rep": int(a.get("repetition", -1)),
            "delivered": recv > 0, "pdr": (recv / sent) if sent else float("nan"), "stream": sent >= 5}


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def newcombe(k1, n1, k2, n2):
    """95 % CI for p1 - p2 (Newcombe hybrid score, unpaired; conservative for paired data)."""
    l1, u1 = wilson(k1, n1); l2, u2 = wilson(k2, n2)
    p1, p2 = k1 / n1, k2 / n2
    d = p1 - p2
    lo = d - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    hi = d + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return lo, hi


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def wilcoxon(diffs):
    d = [x for x in diffs if x != 0 and not math.isnan(x)]
    n = len(d)
    if n == 0:
        return float("nan"), 0
    ranked = sorted(range(n), key=lambda i: abs(d[i]))
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(d[ranked[j + 1]]) == abs(d[ranked[i]]):
            j += 1
        for t in range(i, j + 1):
            ranks[ranked[t]] = (i + j) / 2 + 1
        i = j + 1
    wplus = sum(r for r, x in zip(ranks, d) if x > 0)
    mu = n * (n + 1) / 4
    sd = math.sqrt(n * (n + 1) * (2 * n + 1) / 24)
    z = (wplus - mu - math.copysign(0.5, wplus - mu)) / sd if sd else 0
    p = math.erfc(abs(z) / math.sqrt(2))
    return p, n


def tci(diffs):
    d = [x for x in diffs if not math.isnan(x)]
    if len(d) < 2:
        return float("nan"), float("nan"), float("nan")
    m = statistics.mean(d); s = statistics.stdev(d)
    tcrit = {29: 2.045, 28: 2.048, 27: 2.052}.get(len(d) - 1, 1.96)
    h = tcrit * s / math.sqrt(len(d))
    return m, m - h, m + h


runs = [r for r in (record(p) for p in sys.argv[1:]) if r]
print(f"{len(runs)} valid runs\n")
groups = collections.defaultdict(lambda: collections.defaultdict(dict))
for r in runs:
    groups[r["group"]][r["variant"]][r["rep"]] = r

for g in sorted(groups):
    vs = groups[g]
    label = ", ".join(f"{k}={v}" for k, v in g if k != "configname") or "-"
    cfg = dict(g).get("configname", "")
    print(f"=== {cfg} {label}")
    refs = [x for x in ("none", "fixed", "ackTimeout", "dpbha", "cooperative0") if x in vs]
    for v in sorted(vs):
        if v == "none":
            continue
        for ref in refs:
            if ref == v:
                continue
            reps = sorted(set(vs[v]) & set(vs[ref]))
            if not reps:
                continue
            A = [vs[v][i] for i in reps]; B = [vs[ref][i] for i in reps]
            n = len(reps); ka = sum(x["delivered"] for x in A); kb = sum(x["delivered"] for x in B)
            b = sum(1 for x, y in zip(A, B) if x["delivered"] and not y["delivered"])
            c = sum(1 for x, y in zip(A, B) if y["delivered"] and not x["delivered"])
            lo, hi = newcombe(ka, n, kb, n)
            line = (f"  {v:>11} vs {ref:<10} n={n:>2}  delivered {ka:>2}/{n} vs {kb:>2}/{n}  "
                    f"diff {ka/n - kb/n:+.2f} [{lo:+.2f},{hi:+.2f}]  rescued {b} broken {c}  McNemar p={mcnemar_exact(b, c):.4f}")
            if A[0]["stream"]:
                diffs = [x["pdr"] - y["pdr"] for x, y in zip(A, B)]
                m, l2, h2 = tci(diffs); pw, nz = wilcoxon(diffs)
                line += f"\n  {'':>11}    packets: mean diff {100*m:+.1f} pp [{100*l2:+.1f},{100*h2:+.1f}]  Wilcoxon p={pw:.4f} (n≠0={nz})"
            print(line)
    print()
