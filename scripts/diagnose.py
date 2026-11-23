#!/usr/bin/env python3
import collections, sys

def parse_sca(path):
    attrs, scalars = {}, collections.defaultdict(dict)
    with open(path, errors="ignore") as f:
        for line in f:
            parts = line.rstrip("\n").split(None, 3)
            if not parts: continue
            if parts[0] in ("attr", "itervar") and len(parts) >= 3:
                attrs[parts[1]] = " ".join(parts[2:]).replace("\\", "").strip('"')
            elif parts[0] == "scalar" and len(parts) == 4:
                try: scalars[parts[1]][parts[2]] = float(parts[3])
                except ValueError: pass
    return attrs, scalars

rows = collections.defaultdict(collections.Counter)
for path in sys.argv[1:]:
    attrs, sc = parse_sca(path)
    if "destDistance" not in sc.get("Scenario.node[0].app[0]", {}): continue
    key = (attrs.get("maxRange", ""), float(attrs.get("bhFraction", "nan")), attrs.get("detection", "?"))
    aodvs = [v for m, v in sc.items() if m.endswith(".aodv")]
    delivered = any(v.get("warningsReceived", 0) > 0 for m, v in sc.items()
                    if m.endswith(".app[0]") and not m.startswith("Scenario.node[0]."))
    c = rows[key]; c["runs"] += 1
    c["passedFakes"] += int(sum(v.get("plausibilityPassedFakes", 0) for v in aodvs))
    if delivered: c["ok"] += 1; continue
    fake = sum(v.get("dropsViaFakeRoute", 0) for v in aodvs)
    gen = sum(v.get("dropsViaGenuineRoute", 0) for v in aodvs)
    c["both" if fake and gen else "fake" if fake else "genuine" if gen else "no drop"] += 1

print(f"{'Rmax':>6} {'bhFrac':>6} {'detect':>12} {'runs':>4} {'ok':>3} | fail: {'fake':>5} {'genuine':>7} {'both':>5} {'no drop':>7} | {'passedFakes':>11}")
for k in sorted(rows):
    c = rows[k]
    print(f"{k[0]:>6} {k[1]:>6.2f} {k[2]:>12} {c['runs']:>4} {c['ok']:>3} |       {c['fake']:>5} {c['genuine']:>7} {c['both']:>5} {c['no drop']:>7} | {c['passedFakes']:>11}")
