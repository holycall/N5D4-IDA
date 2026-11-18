"""Refresh the GitHub README tables and PNGs from the measured benchmark results."""

import json
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import MaxNLocator

from report import BUILDS, EXPECTED, HERE, average, measurements

NAMES = {"arm32-gcc": "ARM32 / GCC", "arm32-llvm": "ARM32 / LLVM",
         "mips-gcc": "MIPS / GCC", "mips-llvm": "MIPS / LLVM"}
INK, MUTED, GRID = "#182c3c", "#445765", "#dce3e8"
BASE, MODEL, LOSS = "#456e9a", "#087666", "#ae542d"
FIGURES = HERE / "figures"


def axes_style(ax):
    ax.spines[:].set_visible(False)
    ax.tick_params(length=0, pad=7, colors=MUTED)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def change_chart(groups):
    labels = [f"{name}   (n={len(rows)})" for name, rows in groups]
    changes = [100 * (average(rows, "refined", "f1") - average(rows, "baseline", "f1"))
               for _, rows in groups]
    fig, ax = plt.subplots(figsize=(8.6, 3.5), layout="constrained")
    axes_style(ax)
    lo, hi = min(*changes, 0), max(*changes, 0)
    span = max(hi - lo, 0.002)
    ax.set_xlim(lo - .26 * span, hi + .18 * span)
    ax.barh(labels, changes, height=.43, color=[LOSS if d < 0 else MODEL for d in changes])
    for i, d in enumerate(changes):
        align, offset = ("right", -5) if d < 0 else ("left", 5)
        ax.annotate(f"{d:+.4f}", (d, i), xytext=(offset, 0), textcoords="offset points",
                    ha=align, va="center", color=INK, fontsize=10)
    ax.invert_yaxis()
    ax.axvline(0, color=INK, lw=1)
    ax.set_xlabel("Change in mean F1 on the 0–100 scale   (IDA + N5D4 minus vanilla IDA)", color=MUTED)
    ax.set_title("Effect of N5D4 on IDA Pro 9.4", loc="left", fontweight="bold", color=INK, pad=13)
    ax.xaxis.set_major_locator(MaxNLocator(nbins=6))
    fig.savefig(FIGURES / "ida-coreutils-change.png", dpi=170, facecolor="white")
    plt.close(fig)


def version_chart(rows):
    fig, (ax, values) = plt.subplots(1, 2, figsize=(8.6, 3.3), sharey=True,
                                     gridspec_kw={"width_ratios": [3, 1]}, layout="constrained")
    axes_style(ax)
    for i, (_, first, second) in enumerate(rows):
        ax.plot([first, second], [i, i], color="#919fa9", lw=2)
        ax.scatter(first, i, marker="s", s=55, facecolors="white", edgecolors=BASE, lw=2, zorder=3)
        ax.scatter(second, i, marker="o", s=25, color=MODEL, zorder=4)
        for x, v in ((.22, first), (.76, second)):
            values.text(x, i, f"{v:.5f}", va="center", ha="center", color=INK, fontsize=10)
    ax.set_yticks(range(len(rows)), [name for name, _, _ in rows])
    ax.set_ylim(len(rows) - .5, -.5)
    ax.set_xlim(.86, 1.006)
    ax.set_xticks([.86, .90, .94, .98, 1.0])
    ax.set_xlabel("Mean F1 on the four base64 builds", color=MUTED)
    ax.set_title("Same binaries across disassembler versions", loc="left", fontweight="bold",
                 color=INK, pad=16)
    values.set_axis_off()
    for x, title in ((.22, "Baseline"), (.76, "+ NSDA")):
        values.text(x, 1.015, title, transform=values.transAxes, ha="center", va="bottom",
                    color=MUTED, weight="bold", fontsize=10)
    handles = [Line2D([], [], marker="s", lw=0, markerfacecolor="white", markeredgewidth=2,
                      markeredgecolor=BASE, label="Baseline"),
               Line2D([], [], marker="o", lw=0, color=MODEL, label="With NSDA")]
    ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(.0, -.17), ncols=2,
              frameon=False, borderaxespad=0)
    fig.savefig(FIGURES / "base64-version-comparison.png", dpi=170, facecolor="white")
    plt.close(fig)


def main():
    corpus = [(NAMES[b], measurements(HERE / "full-results", b)) for b in BUILDS]
    for build, (_, rows) in zip(BUILDS, corpus):
        if len(rows) != EXPECTED[build]:
            raise ValueError(f"{build}: measured {len(rows)} of {EXPECTED[build]} inputs")
    all_rows = [r for _, rows in corpus for r in rows]
    corpus.append(("All binaries", all_rows))
    demo = [measurements(HERE / "results", b)[0] for b in BUILDS]
    versions = [("IDA Pro 9.4", average(demo, "baseline", "f1"),
                 average(demo, "refined", "f1", "artifact_probes"))]
    for version in ("11.3.2", "12.0.4", "12.2"):
        folder = HERE / "ghidra-results" / version
        pairs = []
        for method in ("ghidra", "nsda"):
            results = [json.loads((folder / f"{b}-base64-{method}.json").read_text(encoding="utf-8"))
                       for b in BUILDS]
            assert all(r["sha256"] == i["sha256"] for r, i in zip(results, demo))
            pairs.append(statistics.mean(r["f1"] for r in results))
        versions.append((f"Ghidra {version}", *pairs))
    FIGURES.mkdir(exist_ok=True)
    change_chart(corpus)
    version_chart(versions)
    base, after = (average(all_rows, method, "f1") for method in ("baseline", "refined"))
    effects = [r["refined"]["bytes"]["f1"] - r["baseline"]["bytes"]["f1"] for r in all_rows]
    extra_tp, extra_fp = [sum(r["refined"]["bytes"][key] - r["baseline"]["bytes"][key] for r in all_rows)
                          for key in ("tp", "fp")]
    src = ["## Benchmark results", "",
           f"Across **{len(all_rows)} stripped GNU Coreutils ELF binaries**, vanilla IDA Pro 9.4 scored "
           f"**{base:.5f}** mean code-byte F1. With N5D4, it scored **{after:.5f}**. "
           f"F1 rose on {sum(v > 0 for v in effects)} of the binaries, stayed the same on {effects.count(0)}, "
           f"and fell on {sum(v < 0 for v in effects)}.", "",
           "### IDA before and after N5D4 on the full corpus", "",
           "| Build | Binaries | Vanilla IDA F1 | IDA + N5D4 F1 | Change in F1 (0–100 scale) |",
           "|---|---:|---:|---:|---:|"]
    for name, rows in corpus:
        a, b = (average(rows, method, "f1") for method in ("baseline", "refined"))
        src.append(f"| {name} | {len(rows)} | {a:.5f} | {b:.5f} | {100 * (b - a):+.4f} |")
    src += ["", f"N5D4 recovered **{extra_tp:,} additional bytes of labeled code** and classified "
            f"**{extra_fp:,} additional bytes outside the ground-truth code set** as code. "
            "Each binary has equal weight in the mean. The benchmark used a score threshold of 0.50 "
            "and included defined data in executable segments.", "",
            "![Change in mean IDA F1 by architecture and compiler](evaluation/figures/ida-coreutils-change.png)",
            "", "### IDA and Ghidra on the same four base64 builds", "",
            "Each version analyzed the same four files. Baseline F1 counts code bytes. The NSDA column "
            "uses the authors’ scorer, which samples blocks at four-byte intervals. Both scoring methods "
            "gave the same F1 for the IDA port on these four inputs.", "",
            "| Disassembler | Baseline mean F1 | Mean F1 with NSDA |",
            "|---|---:|---:|"]
    for name, first, second in versions:
        src.append(f"| {name} | {first:.5f} | {second:.5f} |")
    _, gh_base, gh_after = versions[-1]
    best = max((score, name, stage) for name, vanilla, nsda in versions
               for stage, score in (("baseline", vanilla), ("with NSDA", nsda)))
    src += ["", f"On Ghidra 12.2, the authors’ implementation raised mean F1 by "
            f"**{100 * (gh_after - gh_base):.2f} points** on the 0–100 scale. "
            f"The highest mean F1 on these four files was {best[0]:.5f} ({best[1]}, {best[2]}).",
            "", "![Baseline and refined F1 for IDA and three Ghidra releases](evaluation/figures/base64-version-comparison.png)",
            "", "The direct comparison of IDA 9.4 and Ghidra 12.2 covers the four demo builds. "
            "The full report compares the corpus results with Tables 4 and 9 of the paper and gives "
            "precision, recall, byte counts, and reproduction commands. "
            "[Evaluation report](evaluation/REPORT.md) · [Authors’ evaluation code](https://github.com/gdjs2/NSDA) · "
            "[Coreutils dataset](https://github.com/gdjs2/NSDA-coreutils-dataset)"]
    readme = HERE.parent / "README.md"
    before, marker, rest = readme.read_text(encoding="utf-8").partition("<!-- benchmark:start -->")
    _, end_marker, after_text = rest.partition("<!-- benchmark:end -->")
    if not (marker and end_marker):
        raise ValueError("Missing README result markers")
    readme.write_text(before + marker + "\n\n" + "\n".join(src) + "\n\n" + end_marker + after_text,
                      encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
