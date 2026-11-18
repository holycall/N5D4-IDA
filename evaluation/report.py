"""Build the benchmark report from completed per-binary measurements."""

import json
import statistics
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILDS = ("arm32-gcc", "arm32-llvm", "mips-gcc", "mips-llvm")
EXPECTED = dict(zip(BUILDS, (102, 104, 102, 104)))
ARTIFACT = "21814efab2155dab48c74eb06e43deb6b24a4970"
DATASET = "9962bca2c5073e4ddac09a7941479f526597c36d"
# F1 transcribed from the authors' demo-f1.png and paper Table 4, respectively.
DEMO_F1 = dict(zip(BUILDS, ((.9799, .9975), (.8880, .9930), (.9202, .9898), (.7375, .9823))))
PAPER_F1 = dict(zip(BUILDS, ((.9768, .9966), (.9499, .9940), (.9237, .9889), (.8800, .9908))))
PAPER12_F1 = dict(zip(BUILDS, ((.9752, .9973), (.9594, .9934), (.9310, .9893), (.7817, .9804))))


def measurements(folder, build):
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((folder / build).glob("*.json"))]


def average(rows, method, key, scoring="bytes"):
    return statistics.mean(r[method][scoring][key] for r in rows)


def table(lines, headers):
    lines.extend(["", "| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"])


def row(lines, *cells):
    lines.append("| " + " | ".join(map(str, cells)) + " |")


def demo_section(lines):
    demo = [measurements(HERE / "results", build) for build in BUILDS]
    if not all(len(group) == 1 and group[0]["binary"] == "base64" for group in demo):
        raise ValueError("Expected four base64 measurements")
    lines += ["## Official base64 demo", "",
              "The authors built the same program for two architectures with two compilers. "
              "Precision (P), recall (R), and F1 below count individual code bytes. "
              "The last column counts additional false-positive bytes after applying N5D4."]
    table(lines, ("Build", "Vanilla IDA P / R / F1", "IDA + N5D4 P / R / F1",
                  "Blocks converted", "Additional false-positive bytes"))
    for build, (r,) in zip(BUILDS, demo):
        triplets = [" / ".join(f"{r[m]['bytes'][k]:.5f}" for k in ("precision", "recall", "f1"))
                    for m in ("baseline", "refined")]
        row(lines, build, *triplets, r["applied_blocks"], r["refined"]["bytes"]["fp"] - r["baseline"]["bytes"]["fp"])
    all_demo = [r for (r,) in demo]
    lines += ["", f"Mean F1 across the four builds was {average(all_demo, 'baseline', 'f1'):.5f} for vanilla IDA "
              f"and {average(all_demo, 'refined', 'f1'):.5f} with N5D4. "
              "On both ARM builds, IDA’s initial analysis found every labeled code byte."]
    lines += ["", "### Comparison with the authors’ demo results", "",
              "The two Ghidra columns give F1 values from the authors’ demo. The two IDA columns "
              "give our measurements on the same files. The baseline counts code bytes, while the "
              "refined result uses the authors’ four-byte sampling interval."]
    table(lines, ("Build", "Ghidra", "Ghidra + NSDA", "Vanilla IDA", "IDA + N5D4"))
    for build, (r,) in zip(BUILDS, demo):
        row(lines, build, *(f"{x:.5f}" for x in (*DEMO_F1[build], r["baseline"]["bytes"]["f1"],
                                                  r["refined"]["artifact_probes"]["f1"])))
    lines += ["", f"[Authors’ demo results](https://github.com/gdjs2/NSDA/blob/{ARTIFACT}/imgs/demo-f1.png)"]
    lines += ["", "### How the paper selected its baselines", "",
              "Section 5.1 identifies one representative per disassembly approach. The authors chose "
              "Ghidra 11.3.2 for linear and recursive traversal, DDisasm for superset disassembly, "
              "and Loadstar for neural disassembly. Section 1 acknowledges that IDA Pro can achieve "
              "high accuracy on standard formats. The authors give no separate reason for omitting "
              "IDA from Table 4. [Paper, Sections 1 and 5.1](https://doi.org/10.1145/3830454.3832592)"]
    case_path = HERE / "vanilla-ida-switch.json"
    if case_path.exists():
        case = json.loads(case_path.read_text(encoding="utf-8"))
        recovered = sum(x["code_head"] and x["xref_from_dispatch"] for x in case["paper_targets"])
        lines += ["", "### Jump table from Section 5.6", "",
                  f"In the ARM32 GCC build of `base64`, vanilla IDA 9.4 identified the dispatch "
                  f"instruction at `{case['dispatch']}` and a jump table at `{case['table']}` "
                  f"with {len(case['cases'])} cases. Of the three targets that Ghidra missed in Listing 1, "
                  f"IDA recognized {recovered} as instruction starts and recorded a code reference from "
                  "the dispatch to each. We checked the addresses against Listings 1 and 2 and the words "
                  "in the binary’s jump table. [Raw IDA jump-table results](vanilla-ida-switch.json)"]
        table(lines, ("Case", "Table entry address", "Target", "Instruction start", "Reference from dispatch"))
        for x in case["paper_targets"]:
            row(lines, x["index"], x["slot"], x["target"], "Yes" if x["code_head"] else "No",
                "Yes" if x["xref_from_dispatch"] else "No")


def versions_section(lines):
    lines += ["", "## Ghidra version comparison", "",
              "Table 9 in Appendix B reports the following F1 scores for the full Coreutils corpus. "
              "When the authors moved from Ghidra 11.3.2 to 12.0.4, baseline recall on MIPS LLVM fell "
              "from 0.7921 to 0.6483. With NSDA, recall on that build fell from 0.9834 to 0.9617."]
    table(lines, ("Build", "11.3.2", "12.0.4", "11.3.2 + NSDA", "12.0.4 + NSDA"))
    for build in BUILDS:
        g11, ns11 = PAPER_F1[build]
        g12, ns12 = PAPER12_F1[build]
        row(lines, build, *(f"{x:.4f}" for x in (g11, g12, ns11, ns12)))
    lines += ["", "For the PLC samples in the same table, baseline Ghidra F1 fell from 0.9875 to "
              "0.2324 on NS1 and from 0.9875 to 0.2206 on NS2. With NSDA on 12.0.4, the authors "
              "reported 0.9891 and 0.9910 respectively. The IDA evaluation here covers standard "
              "Coreutils ELF binaries. [Paper, Appendix B](https://doi.org/10.1145/3830454.3832592)"]
    dirs = HERE / "ghidra-results"
    if not dirs.exists():
        return
    runs = {}
    for p in dirs.glob("*/*.json"):
        result = json.loads(p.read_text(encoding="utf-8"))
        runs[result["ghidra"], result["build"], result["evaluator"]] = result
    if not runs:
        return
    lines += ["", "### Local runs on identical demo inputs", "",
              "Each Ghidra version analyzed the authors’ stripped `base64` binaries using the original "
              "`GhidraEvaluator` and `NSDAEvaluator`. We matched each input by SHA-256, read the base "
              "addresses and training parameters from the authors’ TOML files, and used the PyGhidra "
              "package for each release. The runs used Temurin 25.0.1 and trained on the CPU with seed 42."]
    table(lines, ("Disassembler", "Baseline mean F1", "Mean F1 with NSDA", "Change in F1 (0–100 scale)"))
    for release in sorted({k[0] for k in runs}):
        if all((release, b, m) in runs for b in BUILDS for m in ("ghidra", "nsda")):
            first, second = [statistics.mean(runs[release, b, m]["f1"] for b in BUILDS)
                             for m in ("ghidra", "nsda")]
            row(lines, f"Ghidra {release}", f"{first:.5f}", f"{second:.5f}", f"{100*(second-first):+.3f}")
    sample = [measurements(HERE / "results", b)[0] for b in BUILDS]
    first = average(sample, "baseline", "f1")
    second = average(sample, "refined", "f1", "artifact_probes")
    row(lines, "IDA Pro 9.4", f"{first:.5f}", f"{second:.5f}", f"{100*(second-first):+.3f}")
    lines += ["", "#### F1 by binary"]
    table(lines, ("Ghidra version", "Build", "Vanilla Ghidra", "Ghidra + NSDA", "Vanilla IDA", "IDA + N5D4"))
    for release in sorted({k[0] for k in runs}):
        for build in BUILDS:
            pair = [runs.get((release, build, method)) for method in ("ghidra", "nsda")]
            if not all(pair):
                continue
            (ida,) = measurements(HERE / "results", build)
            assert all(x["sha256"] == ida["sha256"] for x in pair)
            row(lines, release, build, *(f"{x:.5f}" for x in (
                pair[0]["f1"], pair[1]["f1"], ida["baseline"]["bytes"]["f1"],
                ida["refined"]["artifact_probes"]["f1"])))
    lines += ["", "[Raw Ghidra results](ghidra-results/) · [Authors’ configuration for Ghidra 12.x]"
              f"(https://github.com/gdjs2/NSDA/blob/{ARTIFACT}/configs/main-12.toml)"]


def corpus_section(lines):
    groups = {b: measurements(HERE / "full-results", b) for b in BUILDS}
    combined = [r for group in groups.values() for r in group]
    lines.extend(["", "## Full Coreutils corpus", "",
                  f"The benchmark completed **{len(combined)} of {sum(EXPECTED.values())} binaries**. "
                  "Each stripped ELF binary from the authors’ GNU Coreutils 9.9 dataset carries equal "
                  "weight in the mean."])
    if not combined:
        return
    table(lines, ("Build", "Completed / total", "Vanilla IDA P / R / F1", "IDA + N5D4 P / R / F1",
                  "F1 higher / equal / lower"))
    for name, group in [*groups.items(), ("All binaries", combined)]:
        if not group:
            continue
        diff = [r["refined"]["bytes"]["f1"] - r["baseline"]["bytes"]["f1"] for r in group]
        target = EXPECTED.get(name, sum(EXPECTED.values()))
        triplets = [" / ".join(f"{average(group, m, k):.5f}" for k in ("precision", "recall", "f1"))
                    for m in ("baseline", "refined")]
        row(lines, name, f"{len(group)} / {target}", *triplets,
            f"{sum(d > 0 for d in diff)} / {diff.count(0)} / {sum(d < 0 for d in diff)}")
    for key, label in [("tp", "true-positive"), ("fp", "false-positive")]:
        count = sum(r["refined"]["bytes"][key] - r["baseline"]["bytes"][key] for r in combined)
        lines += ["", f"The total {label} byte count changed by **{count:+,}** after applying N5D4."]
    ordered = sorted(combined, key=lambda r: r["refined"]["bytes"]["f1"] - r["baseline"]["bytes"]["f1"])
    lines += ["", "The largest increase and decrease in F1 occurred on these binaries."]
    table(lines, ("Build / binary", "Vanilla IDA F1", "IDA + N5D4 F1",
                  "Change in true-positive bytes", "Change in false-positive bytes"))
    for r in (ordered[-1], ordered[0]):
        a, b = r["baseline"]["bytes"], r["refined"]["bytes"]
        row(lines, f"{r['build']} / {r['binary']}", f"{a['f1']:.6f}", f"{b['f1']:.6f}",
            f"{b['tp'] - a['tp']:+d}", f"{b['fp'] - a['fp']:+d}")
    isolated_path = HERE / "clean-baseline.json"
    if isolated_path.exists():
        isolated = json.loads(isolated_path.read_text(encoding="utf-8"))
        pairs = [(r["baseline"]["bytes"], isolated[r["build"]][r["binary"]])
                 for r in combined if r["binary"] in isolated.get(r["build"], {})]
        lines += ["", "An independent run used an empty `IDAUSR` profile and measured vanilla IDA "
                  "directly from instruction starts and item sizes, before loading any port code. "
                  f"True-positive, false-positive, and false-negative byte counts matched on "
                  f"{sum(a == b for a, b in pairs)} of {len(pairs)} comparable binaries. "
                  "[Independent baseline measurements](clean-baseline.json)"]
    lines += ["", "### Comparison with Table 4 of the paper", "",
              "The Ghidra columns show F1 as reported by the authors for each build group. The IDA "
              "columns show the means measured here. The port uses IDA’s decoder and register-access "
              "information, so both the underlying disassembler and the feature extraction differ."]
    table(lines, ("Build", "Paper: Ghidra", "Paper: Ghidra + NSDA", "Measured vanilla IDA",
                  "Measured IDA + N5D4 (four-byte sampling)"))
    for name, group in groups.items():
        if group:
            row(lines, name, *(f"{x:.5f}" for x in (*PAPER_F1[name], average(group, "baseline", "f1"),
                                                     average(group, "refined", "f1", "artifact_probes"))))
    lines += ["", "[Neurosymbolic Disassembly, Table 4](https://doi.org/10.1145/3830454.3832592)"]


def main():
    lines = ["# Evaluating N5D4 on IDA Pro 9.4", ""]
    demo_section(lines)
    corpus_section(lines)
    versions_section(lines)
    lines += ["", "## Method", "",
              "- For each of the four builds, we used the authors’ TOML configuration and dataset to select "
              "the inputs, base address, pass limit, and epoch limit. We opened a copy of each stripped ELF "
              "in a fresh IDB, waited for automatic analysis, and measured the baseline. We then applied "
              "the port to the same IDB and scored it again after the final reanalysis.",
              "- Each binary got a fresh model with seed 42, up to 500 epochs per pass, at most five passes, "
              "and a score threshold of 0.50. To match the scope of the authors’ evaluator, candidates "
              "included both undefined regions and existing data items in executable segments. The plugin’s "
              "default interactive preview considers undefined regions only.",
              "- A CSV row with `ground_truth` equal to 0 marks four code bytes starting at its address. "
              "Only the scorer reads the labels, after training and IDB updates finish. We aligned IDA "
              "addresses using the file offset of the ELF `.text` section and compared the four raw bytes "
              "of every positive row with the IDB. Each result JSON includes the match count, file hashes, "
              "training device, loss by pass, and elapsed time.",
              "- The primary metric compares all bytes IDA marked as code in initialized, regular segments "
              "with the ground-truth code set. Every predicted code byte outside the set counts as a false "
              "positive. The authors’ NSDA scorer samples at four-byte intervals from each block start. "
              "Sampled ground-truth positions in data or undefined blocks count as false negatives. "
              "The two scoring methods can therefore have different denominators.",
              "- The local runs used Windows, IDA Pro 9.4 (260714), Python 3.14.7, PyTorch 2.15.0 on CPU, "
              "and LTNtorch 1.0.2. The authors used Ubuntu, Ghidra 11.3.2, and CUDA. Hardware and runtime "
              "differences limit direct timing comparisons.",
              "", f"[Authors’ configurations](https://github.com/gdjs2/NSDA/tree/{ARTIFACT}/configs) · "
              f"[Ground-truth loader](https://github.com/gdjs2/NSDA/blob/{ARTIFACT}/src/DataLoader.py) · "
              f"[NSDA scorer](https://github.com/gdjs2/NSDA/blob/{ARTIFACT}/src/ltn_helper.py) · "
              f"[Dataset revision](https://github.com/gdjs2/NSDA-coreutils-dataset/tree/{DATASET})", "",
              "## Reproduce the results", "",
              "Run these commands from the project root to obtain the evaluation code and dataset.", "",
              "```powershell", "git clone https://github.com/gdjs2/NSDA.git evaluation/upstream/NSDA",
              f"git -C evaluation/upstream/NSDA checkout {ARTIFACT}",
              "git clone https://github.com/gdjs2/NSDA-coreutils-dataset.git evaluation/upstream/coreutils",
              f"git -C evaluation/upstream/coreutils checkout {DATASET}", "```", "",
              "Run the IDA benchmarks from the project root using a Python interpreter configured for "
              "IDA’s `idalib`. The training worker uses the project’s `.venv`.", "", "```powershell",
              "python -X utf8 -u evaluation/benchmark.py",
              "python -X utf8 -u evaluation/benchmark.py --config evaluation/upstream/NSDA/configs/main.toml --output evaluation/full-results --resume",
              "python evaluation/report.py", "```", "",
              "Each binary has a separate JSON result. Use `--build` to restrict the full evaluation "
              "to one architecture and compiler combination. [Demo results](results/) · "
              "[Full corpus results](full-results/)", "",
              "To reproduce the Ghidra comparison, install `pyghidra==2.2.0`, `rich==14.2.0`, and "
              "`loguru==0.7.3` in the project’s virtual environment. For Ghidra 11.3.2, run the command "
              "below with its installation directory. For 12.x, extract that release’s PyGhidra wheel "
              "from `Ghidra/Features/PyGhidra/pypkg/dist` into a separate directory and add "
              "`--pyghidra-path <extracted-wheel-directory>`.", "",
              "```powershell", ".\\.venv\\Scripts\\python.exe evaluation/ghidra_demo.py --ghidra <Ghidra-install-directory>",
              "```", "", "To repeat the independent baseline check, run "
              "`python evaluation/clean_baseline.py --ida-dir <IDA-install-directory>`.", "",
              "Once the full IDA corpus and the three Ghidra demo runs are available, run "
              "`python evaluation/publish_results.py` in a Python environment with Matplotlib installed "
              "to refresh the README tables and figures.", ""]
    (HERE / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
