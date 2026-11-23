# Geometric plausibility checks against AODV blackhole attacks in VANETs

Simulation code, configurations, analysis scripts and result summaries for the paper

> P. Sharma, *Geometric Plausibility Checks Against Blackhole Attacks in VANETs: A Vehicular
> Evaluation and a Cooperative Self-Calibrating Range Bound* (submitted).

The repository reproduces every table and figure in the paper. Raw OMNeT++ result files
(`.sca`) are not included because of their size; every run can be regenerated from the
configurations here with fixed seeds (seed-set = repetition), and the summary tables and
statistical tests produced from them are in `results_summary/`.

## Requirements

| Tool | Version used |
|---|---|
| OMNeT++ | 6.3.0 |
| INET | 4.5.4 |
| Veins (with veins_inet) | 5.3.1 |
| SUMO | 1.18.0 |
| Python | 3.8 or later (standard library only) |

Tested under WSL (Ubuntu) using `opp_env`. Expected layout, side by side:

```
default_workspace/
  inet-4.5.4/
  veins-5.3.1/
  Vanet_Blackhole/      <- this repository
```

## Build

```bash
cd Vanet_Blackhole/src
opp_makemake -f --deep -o Vanet_Blackhole -KINET_PROJ=../../inet-4.5.4 -DINET_IMPORT \
  -I'$(INET_PROJ)/src' -L'$(INET_PROJ)/src' -lINET'$(D)'
cd .. && make
```

## Run

```bash
cd veins_sims/grid
V=../../../veins-5.3.1
RUN="../../out/clang-release/src/Vanet_Blackhole -u Cmdenv -n .:../../src:../../../inet-4.5.4/src:$V/src/veins:$V/subprojects/veins_inet/src/veins_inet -l $V/out/clang-release/src/veins -l $V/subprojects/veins_inet/out/clang-release/src/veins_inet"
$RUN -c SweepFull -q numruns                  # check the run count (1350)
opp_runall -j$(nproc) $RUN -c SweepFull       # run a configuration
```

## Configurations and the paper

| Config (`veins_sims/grid/omnetpp.ini`) | Runs | Paper |
|---|---|---|
| `General`, `BlackholeAttack`, `BlackholeWithMitigation` (`simulations/omnetpp.ini`) | 3 | Section 6.1, static 4-node validation |
| `SweepFull` | 1350 | Sections 6.2 to 6.5, Figure 5 (`Sweep` is the same design at R_max = 330 m only, 450 runs) |
| `Density` | 900 | Section 6.8 |
| `Stream` | 450 | Section 6.9 |
| `Highway` | 450 | Section 6.10 |
| `Adaptive` + `Coop` | 1080 + 540 | Section 6.11 (self-calibrating bounds) |
| `HighwayCoop` | 180 | Section 6.11 (highway) |
| `CoopFading` | 360 | Section 6.11 (Nakagami fading) |
| `PosError` | 1080 | Section 6.12 |
| `DpbhaGrid`, `DpbhaHighway` | 900 | Section 6.13 (controlled comparison with DPBHA) |
| `DpbhaSensGrid`, `DpbhaSensHighway` | 840 | Section 6.13 (DPBHA sensitivity) |
| `CoopPoisonGrid`, `CoopPoisonHighway` | 180 | Section 6.14 (poisoning the cooperative bound) |
| `Visual` | 1 (`-r 90`) | Figure 4 |

## Analysis

All scripts read `.sca` files and print plain-text tables.

```bash
python3 scripts/paired_stats.py results/Stream-*.sca  > stats.txt   # McNemar, Newcombe CI, Wilcoxon
python3 scripts/analyze_adaptive.py results/Adaptive-*.sca results/Coop-*.sca
python3 scripts/analyze_dpbha.py results/Dpbha*-*.sca
python3 scripts/analyze_poison.py results/CoopPoison*-*.sca
```

## Code overview (`src/`)

| File | Role |
|---|---|
| `VanetAodv.{h,cc,ned}` | AODV subclass: blackhole attacker, acknowledgement-timeout defence, geometric plausibility check (fixed, adaptive and cooperative bounds), beacon position error and staleness, ground-truth instrumentation |
| `VanetAodvDpbha.cc`, `DpbhaRrep.h` | DPBHA (Malik et al., Sensors 2022) as a comparison scheme, with optional idealised alarm |
| `AccidentApp.*` | Accident warning source and receivers, acknowledgements, delivery statistics |

## License

Code: MIT (see `LICENSE`). Result summaries: CC BY 4.0.
INET, Veins and SUMO are separate projects under their own licenses and are not included.

## Citation

If you use this code, please cite the paper above and the archived version of this
repository: [doi:10.5281/zenodo.24455344](https://doi.org/10.5281/zenodo.24455344) (v1.0).
