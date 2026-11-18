# Evaluating N5D4 on IDA Pro 9.4

## Official base64 demo

The authors built the same program for two architectures with two compilers. Precision (P), recall (R), and F1 below count individual code bytes. The last column counts additional false-positive bytes after applying N5D4.

| Build | Vanilla IDA P / R / F1 | IDA + N5D4 P / R / F1 | Blocks converted | Additional false-positive bytes |
| --- | --- | --- | --- | --- |
| arm32-gcc | 1.00000 / 1.00000 / 1.00000 | 0.99970 / 1.00000 / 0.99985 | 1 | 8 |
| arm32-llvm | 1.00000 / 1.00000 / 1.00000 | 0.99922 / 1.00000 / 0.99961 | 2 | 20 |
| mips-gcc | 1.00000 / 0.99495 / 0.99747 | 0.99903 / 0.99495 / 0.99699 | 1 | 36 |
| mips-llvm | 1.00000 / 0.99576 / 0.99788 | 1.00000 / 0.99576 / 0.99788 | 0 | 0 |

Mean F1 across the four builds was 0.99884 for vanilla IDA and 0.99858 with N5D4. On both ARM builds, IDA’s initial analysis found every labeled code byte.

### Comparison with the authors’ demo results

The two Ghidra columns give F1 values from the authors’ demo. The two IDA columns give our measurements on the same files. The baseline counts code bytes, while the refined result uses the authors’ four-byte sampling interval.

| Build | Ghidra | Ghidra + NSDA | Vanilla IDA | IDA + N5D4 |
| --- | --- | --- | --- | --- |
| arm32-gcc | 0.97990 | 0.99750 | 1.00000 | 0.99985 |
| arm32-llvm | 0.88800 | 0.99300 | 1.00000 | 0.99961 |
| mips-gcc | 0.92020 | 0.98980 | 0.99747 | 0.99699 |
| mips-llvm | 0.73750 | 0.98230 | 0.99788 | 0.99788 |

[Authors’ demo results](https://github.com/gdjs2/NSDA/blob/21814efab2155dab48c74eb06e43deb6b24a4970/imgs/demo-f1.png)

### How the paper selected its baselines

Section 5.1 identifies one representative per disassembly approach. The authors chose Ghidra 11.3.2 for linear and recursive traversal, DDisasm for superset disassembly, and Loadstar for neural disassembly. Section 1 acknowledges that IDA Pro can achieve high accuracy on standard formats. The authors give no separate reason for omitting IDA from Table 4. [Paper, Sections 1 and 5.1](https://doi.org/10.1145/3830454.3832592)

### Jump table from Section 5.6

In the ARM32 GCC build of `base64`, vanilla IDA 9.4 identified the dispatch instruction at `0x15c74` and a jump table at `0x15c7c` with 10 cases. Of the three targets that Ghidra missed in Listing 1, IDA recognized 3 as instruction starts and recorded a code reference from the dispatch to each. We checked the addresses against Listings 1 and 2 and the words in the binary’s jump table. [Raw IDA jump-table results](vanilla-ida-switch.json)

| Case | Table entry address | Target | Instruction start | Reference from dispatch |
| --- | --- | --- | --- | --- |
| 1 | 0x15c80 | 0x15d68 | Yes | Yes |
| 2 | 0x15c84 | 0x15d84 | Yes | Yes |
| 3 | 0x15c88 | 0x15da8 | Yes | Yes |

## Full Coreutils corpus

The benchmark completed **412 of 412 binaries**. Each stripped ELF binary from the authors’ GNU Coreutils 9.9 dataset carries equal weight in the mean.

| Build | Completed / total | Vanilla IDA P / R / F1 | IDA + N5D4 P / R / F1 | F1 higher / equal / lower |
| --- | --- | --- | --- | --- |
| arm32-gcc | 102 / 102 | 1.00000 / 0.99999 / 1.00000 | 0.99977 / 1.00000 / 0.99989 | 0 / 48 / 54 |
| arm32-llvm | 104 / 104 | 1.00000 / 0.99998 / 0.99999 | 0.99964 / 0.99998 / 0.99981 | 0 / 40 / 64 |
| mips-gcc | 102 / 102 | 1.00000 / 0.99514 / 0.99756 | 0.99973 / 0.99514 / 0.99743 | 0 / 65 / 37 |
| mips-llvm | 104 / 104 | 1.00000 / 0.99604 / 0.99801 | 0.99997 / 0.99604 / 0.99800 | 1 / 93 / 10 |
| All binaries | 412 / 412 | 1.00000 / 0.99779 / 0.99889 | 0.99978 / 0.99779 / 0.99878 | 1 / 246 / 165 |

The total true-positive byte count changed by **+16** after applying N5D4.

The total false-positive byte count changed by **+3,848** after applying N5D4.

The largest increase and decrease in F1 occurred on these binaries.

| Build / binary | Vanilla IDA F1 | IDA + N5D4 F1 | Change in true-positive bytes | Change in false-positive bytes |
| --- | --- | --- | --- | --- |
| mips-llvm / expr | 0.999505 | 0.999516 | +4 | +0 |
| mips-gcc / false | 0.996794 | 0.995973 | +0 | +36 |

An independent run used an empty `IDAUSR` profile and measured vanilla IDA directly from instruction starts and item sizes, before loading any port code. True-positive, false-positive, and false-negative byte counts matched on 412 of 412 comparable binaries. [Independent baseline measurements](clean-baseline.json)

### Comparison with Table 4 of the paper

The Ghidra columns show F1 as reported by the authors for each build group. The IDA columns show the means measured here. The port uses IDA’s decoder and register-access information, so both the underlying disassembler and the feature extraction differ.

| Build | Paper: Ghidra | Paper: Ghidra + NSDA | Measured vanilla IDA | Measured IDA + N5D4 (four-byte sampling) |
| --- | --- | --- | --- | --- |
| arm32-gcc | 0.97680 | 0.99660 | 1.00000 | 0.99989 |
| arm32-llvm | 0.94990 | 0.99400 | 0.99999 | 0.99981 |
| mips-gcc | 0.92370 | 0.98890 | 0.99756 | 0.99743 |
| mips-llvm | 0.88000 | 0.99080 | 0.99801 | 0.99800 |

[Neurosymbolic Disassembly, Table 4](https://doi.org/10.1145/3830454.3832592)

## Ghidra version comparison

Table 9 in Appendix B reports the following F1 scores for the full Coreutils corpus. When the authors moved from Ghidra 11.3.2 to 12.0.4, baseline recall on MIPS LLVM fell from 0.7921 to 0.6483. With NSDA, recall on that build fell from 0.9834 to 0.9617.

| Build | 11.3.2 | 12.0.4 | 11.3.2 + NSDA | 12.0.4 + NSDA |
| --- | --- | --- | --- | --- |
| arm32-gcc | 0.9768 | 0.9752 | 0.9966 | 0.9973 |
| arm32-llvm | 0.9499 | 0.9594 | 0.9940 | 0.9934 |
| mips-gcc | 0.9237 | 0.9310 | 0.9889 | 0.9893 |
| mips-llvm | 0.8800 | 0.7817 | 0.9908 | 0.9804 |

For the PLC samples in the same table, baseline Ghidra F1 fell from 0.9875 to 0.2324 on NS1 and from 0.9875 to 0.2206 on NS2. With NSDA on 12.0.4, the authors reported 0.9891 and 0.9910 respectively. The IDA evaluation here covers standard Coreutils ELF binaries. [Paper, Appendix B](https://doi.org/10.1145/3830454.3832592)

### Local runs on identical demo inputs

Each Ghidra version analyzed the authors’ stripped `base64` binaries using the original `GhidraEvaluator` and `NSDAEvaluator`. We matched each input by SHA-256, read the base addresses and training parameters from the authors’ TOML files, and used the PyGhidra package for each release. The runs used Temurin 25.0.1 and trained on the CPU with seed 42.

| Disassembler | Baseline mean F1 | Mean F1 with NSDA | Change in F1 (0–100 scale) |
| --- | --- | --- | --- |
| Ghidra 11.3.2 | 0.88142 | 0.99051 | +10.909 |
| Ghidra 12.0.4 | 0.88699 | 0.99091 | +10.392 |
| Ghidra 12.2 | 0.88067 | 0.99002 | +10.935 |
| IDA Pro 9.4 | 0.99884 | 0.99858 | -0.026 |

#### F1 by binary

| Ghidra version | Build | Vanilla Ghidra | Ghidra + NSDA | Vanilla IDA | IDA + N5D4 |
| --- | --- | --- | --- | --- | --- |
| 11.3.2 | arm32-gcc | 0.97985 | 0.99758 | 1.00000 | 0.99985 |
| 11.3.2 | arm32-llvm | 0.88803 | 0.99250 | 1.00000 | 0.99961 |
| 11.3.2 | mips-gcc | 0.92025 | 0.98958 | 0.99747 | 0.99699 |
| 11.3.2 | mips-llvm | 0.73753 | 0.98237 | 0.99788 | 0.99788 |
| 12.0.4 | arm32-gcc | 0.97994 | 0.99750 | 1.00000 | 0.99985 |
| 12.0.4 | arm32-llvm | 0.91023 | 0.99320 | 1.00000 | 0.99961 |
| 12.0.4 | mips-gcc | 0.92025 | 0.99067 | 0.99747 | 0.99699 |
| 12.0.4 | mips-llvm | 0.73753 | 0.98226 | 0.99788 | 0.99788 |
| 12.2 | arm32-gcc | 0.97583 | 0.99750 | 1.00000 | 0.99985 |
| 12.2 | arm32-llvm | 0.88908 | 0.99226 | 1.00000 | 0.99961 |
| 12.2 | mips-gcc | 0.92025 | 0.98821 | 0.99747 | 0.99699 |
| 12.2 | mips-llvm | 0.73753 | 0.98211 | 0.99788 | 0.99788 |

[Raw Ghidra results](ghidra-results/) · [Authors’ configuration for Ghidra 12.x](https://github.com/gdjs2/NSDA/blob/21814efab2155dab48c74eb06e43deb6b24a4970/configs/main-12.toml)

## Method

- For each of the four builds, we used the authors’ TOML configuration and dataset to select the inputs, base address, pass limit, and epoch limit. We opened a copy of each stripped ELF in a fresh IDB, waited for automatic analysis, and measured the baseline. We then applied the port to the same IDB and scored it again after the final reanalysis.
- Each binary got a fresh model with seed 42, up to 500 epochs per pass, at most five passes, and a score threshold of 0.50. To match the scope of the authors’ evaluator, candidates included both undefined regions and existing data items in executable segments. The plugin’s default interactive preview considers undefined regions only.
- A CSV row with `ground_truth` equal to 0 marks four code bytes starting at its address. Only the scorer reads the labels, after training and IDB updates finish. We aligned IDA addresses using the file offset of the ELF `.text` section and compared the four raw bytes of every positive row with the IDB. Each result JSON includes the match count, file hashes, training device, loss by pass, and elapsed time.
- The primary metric compares all bytes IDA marked as code in initialized, regular segments with the ground-truth code set. Every predicted code byte outside the set counts as a false positive. The authors’ NSDA scorer samples at four-byte intervals from each block start. Sampled ground-truth positions in data or undefined blocks count as false negatives. The two scoring methods can therefore have different denominators.
- The local runs used Windows, IDA Pro 9.4 (260714), Python 3.14.7, PyTorch 2.15.0 on CPU, and LTNtorch 1.0.2. The authors used Ubuntu, Ghidra 11.3.2, and CUDA. Hardware and runtime differences limit direct timing comparisons.

[Authors’ configurations](https://github.com/gdjs2/NSDA/tree/21814efab2155dab48c74eb06e43deb6b24a4970/configs) · [Ground-truth loader](https://github.com/gdjs2/NSDA/blob/21814efab2155dab48c74eb06e43deb6b24a4970/src/DataLoader.py) · [NSDA scorer](https://github.com/gdjs2/NSDA/blob/21814efab2155dab48c74eb06e43deb6b24a4970/src/ltn_helper.py) · [Dataset revision](https://github.com/gdjs2/NSDA-coreutils-dataset/tree/9962bca2c5073e4ddac09a7941479f526597c36d)

## Reproduce the results

Run these commands from the project root to obtain the evaluation code and dataset.

```powershell
git clone https://github.com/gdjs2/NSDA.git evaluation/upstream/NSDA
git -C evaluation/upstream/NSDA checkout 21814efab2155dab48c74eb06e43deb6b24a4970
git clone https://github.com/gdjs2/NSDA-coreutils-dataset.git evaluation/upstream/coreutils
git -C evaluation/upstream/coreutils checkout 9962bca2c5073e4ddac09a7941479f526597c36d
```

Run the IDA benchmarks from the project root using a Python interpreter configured for IDA’s `idalib`. The training worker uses the project’s `.venv`.

```powershell
python -X utf8 -u evaluation/benchmark.py
python -X utf8 -u evaluation/benchmark.py --config evaluation/upstream/NSDA/configs/main.toml --output evaluation/full-results --resume
python evaluation/report.py
```

Each binary has a separate JSON result. Use `--build` to restrict the full evaluation to one architecture and compiler combination. [Demo results](results/) · [Full corpus results](full-results/)

To reproduce the Ghidra comparison, install `pyghidra==2.2.0`, `rich==14.2.0`, and `loguru==0.7.3` in the project’s virtual environment. For Ghidra 11.3.2, run the command below with its installation directory. For 12.x, extract that release’s PyGhidra wheel from `Ghidra/Features/PyGhidra/pypkg/dist` into a separate directory and add `--pyghidra-path <extracted-wheel-directory>`.

```powershell
.\.venv\Scripts\python.exe evaluation/ghidra_demo.py --ghidra <Ghidra-install-directory>
```

To repeat the independent baseline check, run `python evaluation/clean_baseline.py --ida-dir <IDA-install-directory>`.

Once the full IDA corpus and the three Ghidra demo runs are available, run `python evaluation/publish_results.py` in a Python environment with Matplotlib installed to refresh the README tables and figures.
