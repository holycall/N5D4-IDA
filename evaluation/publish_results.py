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
    src = ["## 평가 결과", "",
           f"GNU Coreutils의 stripped ELF **{len(all_rows)}개**에서 Vanilla IDA의 평균 F1은 "
           f"**{base:.5f}**, N5D4를 적용한 IDA는 **{after:.5f}**였습니다. "
           f"적용 후 F1이 오른 입력은 {sum(v > 0 for v in effects)}개, 같은 입력은 "
           f"{effects.count(0)}개, 낮아진 입력은 {sum(v < 0 for v in effects)}개입니다.", "",
           "### 전체 Coreutils에서 IDA 적용 전후", "",
           "| 빌드 | 바이너리 수 | Vanilla IDA F1 | IDA + N5D4 F1 | 변화 (100점 환산) |",
           "|---|---:|---:|---:|---:|"]
    for name, rows in corpus:
        a, b = (average(rows, method, "f1") for method in ("baseline", "refined"))
        src.append(f"| {name} | {len(rows)} | {a:.5f} | {b:.5f} | {100 * (b - a):+.4f} |")
    src += ["", f"전체에서 새로 찾은 정답 코드는 **{extra_tp:,}바이트**였고, "
            f"데이터를 코드로 잘못 분류한 바이트도 **{extra_fp:,}바이트** 늘었습니다. "
            "각 바이너리의 코드 바이트 F1을 같은 가중치로 평균했습니다. "
            "실행 가능 영역의 기존 데이터도 후보에 포함했으며 모델 점수 기준은 0.50입니다.", "",
            "![아키텍처와 컴파일러별 IDA 적용 전후의 평균 F1 변화](evaluation/figures/ida-coreutils-change.png)",
            "", "### 같은 base64 네 빌드에서 Ghidra와 IDA 비교", "",
            "같은 파일 네 개를 각 버전에서 직접 열어 측정했습니다. 기본 분석은 코드 바이트, "
            "NSDA 적용 후는 논문 아티팩트의 4바이트 간격 채점으로 계산했습니다. "
            "이 네 파일에서 IDA판은 두 채점 방식의 F1이 같았습니다.", "",
            "| 디스어셈블러 | 기본 평균 F1 | NSDA 적용 후 평균 F1 |",
            "|---|---:|---:|"]
    for name, first, second in versions:
        src.append(f"| {name} | {first:.5f} | {second:.5f} |")
    _, gh_base, gh_after = versions[-1]
    best = max((score, name, stage) for name, vanilla, nsda in versions
               for stage, score in (("기본 분석", vanilla), ("NSDA 적용", nsda)))
    src += ["", f"Ghidra 12.2에서 저자 구현은 평균 F1을 100점 환산 **{100 * (gh_after - gh_base):.2f}점** 높였습니다. "
            f"같은 네 파일에서 가장 높은 평균 F1은 {best[1]}의 {best[2]}으로 얻은 {best[0]:.5f}였습니다.",
            "", "![Ghidra 세 버전과 IDA Pro의 기본 및 NSDA 적용 후 F1 비교](evaluation/figures/base64-version-comparison.png)",
            "", "Ghidra 12.2와 IDA 9.4의 버전별 직접 비교 범위는 위 네 빌드입니다. "
            "논문 표 4·9와의 대조, 정밀도·재현율, 오류 바이트 수 및 재현 명령은 "
            "[전체 평가 보고서](evaluation/REPORT.md)에 있습니다. "
            "[저자 평가 코드](https://github.com/gdjs2/NSDA) · "
            "[Coreutils 데이터셋](https://github.com/gdjs2/NSDA-coreutils-dataset)"]
    readme = HERE.parent / "README.md"
    before, marker, rest = readme.read_text(encoding="utf-8").partition("<!-- benchmark:start -->")
    _, end_marker, after_text = rest.partition("<!-- benchmark:end -->")
    if not (marker and end_marker):
        raise ValueError("Missing README result markers")
    readme.write_text(before + marker + "\n\n" + "\n".join(src) + "\n\n" + end_marker + after_text,
                      encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
