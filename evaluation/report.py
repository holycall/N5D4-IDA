"""Build the Korean benchmark report from completed per-binary measurements."""

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
    lines += ["## 공식 데모", "", "동일한 프로그램을 아키텍처와 컴파일러를 달리하여 네 번 빌드했습니다. "
              "다음 표의 P·R·F1은 코드 바이트 기준이며 마지막 열은 추가된 오탐 바이트 수입니다."]
    table(lines, ("빌드", "기본 P / R / F1", "포트 P / R / F1", "적용 블록", "추가 FP"))
    for build, (r,) in zip(BUILDS, demo):
        triplets = [" / ".join(f"{r[m]['bytes'][k]:.5f}" for k in ("precision", "recall", "f1"))
                    for m in ("baseline", "refined")]
        row(lines, build, *triplets, r["applied_blocks"], r["refined"]["bytes"]["fp"] - r["baseline"]["bytes"]["fp"])
    all_demo = [r for (r,) in demo]
    lines += ["", f"네 빌드 평균 F1은 IDA 기본 {average(all_demo, 'baseline', 'f1'):.5f}, "
              f"포트 적용 후 {average(all_demo, 'refined', 'f1'):.5f}입니다. "
              "두 ARM 빌드는 초기 분석에서 이미 모든 정답 코드 바이트를 찾았습니다."]
    lines += ["", "### 저자들이 공개한 같은 입력의 결과와 대조", "",
              "Ghidra 및 Ghidra+NSDA 열은 저자들의 데모 결과표에서 가져왔습니다. "
              "IDA 기본 열은 바이트 단위, IDA+N5D4 열은 저자 NSDA 채점기의 4바이트 간격으로 계산한 F1입니다."]
    table(lines, ("빌드", "Ghidra", "Ghidra+NSDA", "IDA 기본", "IDA+N5D4"))
    for build, (r,) in zip(BUILDS, demo):
        row(lines, build, *(f"{x:.5f}" for x in (*DEMO_F1[build], r["baseline"]["bytes"]["f1"],
                                                  r["refined"]["artifact_probes"]["f1"])))
    lines += ["", f"[저자 공식 데모 결과표](https://github.com/gdjs2/NSDA/blob/{ARTIFACT}/imgs/demo-f1.png)"]
    lines += ["", "### 논문에서 IDA를 비교하지 않은 이유", "",
              "저자들은 §5.1에서 디스어셈블 방식별 대표 도구를 선정했다고 설명합니다. "
              "선형·재귀 탐색에는 Ghidra 11.3.2, superset disassembly에는 DDisasm, "
              "신경망 방식에는 Loadstar를 골랐습니다. §1은 IDA Pro도 표준 형식에서 높은 정확도를 보일 수 있다고 설명합니다. "
              "IDA를 따로 제외한 이유는 논문에 기재되지 않았습니다. 표 4의 비교 대상에는 IDA가 없습니다. "
              "[논문 §1, §5.1](https://doi.org/10.1145/3830454.3832592)"]
    case_path = HERE / "vanilla-ida-switch.json"
    if case_path.exists():
        case = json.loads(case_path.read_text(encoding="utf-8"))
        recovered = sum(x["code_head"] and x["xref_from_dispatch"] for x in case["paper_targets"])
        lines += ["", "### 논문 §5.6의 분기표", "",
                  f"플러그인을 실행하기 전 IDA 9.4에서 ARM32 GCC base64의 {case['dispatch']} 분기를 조사했습니다. "
                  f"IDA가 식별한 테이블 시작은 {case['table']}이고 분기 목적지는 {len(case['cases'])}개입니다. "
                  f"Listing 1에서 Ghidra가 놓친 세 목적지 중 {recovered}개가 IDA에 명령어 시작으로 등록되어 있었고 "
                  "분기 명령으로부터의 코드 참조도 있었습니다. 주소는 Listing 1·2와 실제 테이블의 워드를 기준으로 했습니다. "
                  "[IDA 기본 분기표 원본](vanilla-ida-switch.json)"]
        table(lines, ("케이스", "테이블 주소", "목적지", "코드 시작", "분기 명령의 참조"))
        for x in case["paper_targets"]:
            row(lines, x["index"], x["slot"], x["target"], "예" if x["code_head"] else "아니오",
                "예" if x["xref_from_dispatch"] else "아니오")


def versions_section(lines):
    lines += ["", "## Ghidra 버전별 비교", "", "논문 부록 B, 표 9의 Coreutils 전체 F1입니다. "
              "MIPS LLVM의 경우 Ghidra 기본 재현율이 0.7921에서 0.6483으로 하락했습니다. "
              "NSDA를 적용한 MIPS LLVM의 재현율은 0.9834에서 0.9617로 바뀌었습니다."]
    table(lines, ("빌드", "11.3.2", "12.0.4", "11.3.2 + NSDA", "12.0.4 + NSDA"))
    for build in BUILDS:
        g11, ns11 = PAPER_F1[build]
        g12, ns12 = PAPER12_F1[build]
        row(lines, build, *(f"{x:.4f}" for x in (g11, g12, ns11, ns12)))
    lines += ["", "같은 표에서 PLC NS1의 기본 Ghidra F1은 0.9875에서 0.2324로, NS2는 0.9875에서 0.2206으로 "
              "하락했습니다. 12.0.4에서 NSDA를 적용한 F1은 각각 0.9891, 0.9910입니다. "
              "이번 IDA 평가는 표준 Coreutils ELF를 대상으로 합니다. "
              "[논문 부록 B](https://doi.org/10.1145/3830454.3832592)"]
    dirs = HERE / "ghidra-results"
    if not dirs.exists():
        return
    runs = {}
    for p in dirs.glob("*/*.json"):
        result = json.loads(p.read_text(encoding="utf-8"))
        runs[result["ghidra"], result["build"], result["evaluator"]] = result
    if not runs:
        return
    lines += ["", "### 동일 입력으로 직접 재실행한 데모", "",
              "공식 stripped base64와 저자 저장소의 변경 없는 GhidraEvaluator 및 NSDAEvaluator를 사용했습니다. "
              "버전별 행은 같은 파일 SHA-256을 확인했고, 기준 주소와 학습 파라미터는 저자 TOML에서 읽었습니다. "
              "각 실행에서 Python은 해당 Ghidra 릴리스용 PyGhidra를 로드했습니다. "
              "로컬 Java는 Temurin 25.0.1이며 학습은 CPU에서 seed 42로 실행했습니다. 모든 값은 F1입니다."]
    table(lines, ("디스어셈블러", "네 빌드 기본 평균", "네 빌드 적용 후 평균", "적용 효과 (100점 환산)"))
    for release in sorted({k[0] for k in runs}):
        if all((release, b, m) in runs for b in BUILDS for m in ("ghidra", "nsda")):
            first, second = [statistics.mean(runs[release, b, m]["f1"] for b in BUILDS)
                             for m in ("ghidra", "nsda")]
            row(lines, f"Ghidra {release}", f"{first:.5f}", f"{second:.5f}", f"{100*(second-first):+.3f}")
    sample = [measurements(HERE / "results", b)[0] for b in BUILDS]
    first = average(sample, "baseline", "f1")
    second = average(sample, "refined", "f1", "artifact_probes")
    row(lines, "IDA Pro 9.4", f"{first:.5f}", f"{second:.5f}", f"{100*(second-first):+.3f}")
    lines += ["", "#### 바이너리별 F1"]
    table(lines, ("Ghidra 버전", "빌드", "Ghidra 기본", "Ghidra+NSDA", "Vanilla IDA", "IDA+N5D4"))
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
    lines += ["", "[Ghidra 재실행 측정값](ghidra-results/) · [공식 12.x 평가 설정]"
              f"(https://github.com/gdjs2/NSDA/blob/{ARTIFACT}/configs/main-12.toml)"]


def corpus_section(lines):
    groups = {b: measurements(HERE / "full-results", b) for b in BUILDS}
    combined = [r for group in groups.values() for r in group]
    lines.extend(["", "## 전체 Coreutils 평가", "",
                  f"완료한 입력은 **{len(combined)} / {sum(EXPECTED.values())}개**입니다. "
                  "저자가 제공한 GNU Coreutils 9.9의 stripped ELF에 대해 각 바이너리의 지표를 계산한 뒤 "
                  "같은 가중치로 평균했습니다."])
    if not combined:
        return
    table(lines, ("빌드", "완료 / 대상", "기본 P / R / F1", "포트 P / R / F1", "F1 상승 / 동일 / 하락"))
    for name, group in [*groups.items(), ("전체", combined)]:
        if not group:
            continue
        diff = [r["refined"]["bytes"]["f1"] - r["baseline"]["bytes"]["f1"] for r in group]
        target = EXPECTED.get(name, sum(EXPECTED.values()))
        triplets = [" / ".join(f"{average(group, m, k):.5f}" for k in ("precision", "recall", "f1"))
                    for m in ("baseline", "refined")]
        row(lines, name, f"{len(group)} / {target}", *triplets,
            f"{sum(d > 0 for d in diff)} / {diff.count(0)} / {sum(d < 0 for d in diff)}")
    for key, label in [("tp", "정답 코드"), ("fp", "오탐")]:
        count = sum(r["refined"]["bytes"][key] - r["baseline"]["bytes"][key] for r in combined)
        lines += ["", f"측정한 바이너리 전체에서 {label} 바이트 수의 적용 후 변화량은 **{count:+,}**입니다."]
    ordered = sorted(combined, key=lambda r: r["refined"]["bytes"]["f1"] - r["baseline"]["bytes"]["f1"])
    lines += ["", "F1 변화의 양 끝에 있는 입력은 다음과 같습니다."]
    table(lines, ("빌드 / 프로그램", "기본 F1", "포트 F1", "정답 코드 변화 (바이트)", "오탐 변화 (바이트)"))
    for r in (ordered[-1], ordered[0]):
        a, b = r["baseline"]["bytes"], r["refined"]["bytes"]
        row(lines, f"{r['build']} / {r['binary']}", f"{a['f1']:.6f}", f"{b['f1']:.6f}",
            f"{b['tp'] - a['tp']:+d}", f"{b['fp'] - a['fp']:+d}")
    isolated_path = HERE / "clean-baseline.json"
    if isolated_path.exists():
        isolated = json.loads(isolated_path.read_text(encoding="utf-8"))
        pairs = [(r["baseline"]["bytes"], isolated[r["build"]][r["binary"]])
                 for r in combined if r["binary"] in isolated.get(r["build"], {})]
        lines += ["", "Vanilla IDA 결과는 비어 있는 IDAUSR 프로필에서 포트를 로드하지 않고 독립 검산했습니다. "
                  "이 검산은 IDA의 명령어 시작 주소와 항목 크기를 직접 순회합니다. "
                  f"현재 비교 가능한 {len(pairs)}개 중 TP·FP·FN이 모두 일치한 입력은 "
                  f"{sum(a == b for a, b in pairs)}개입니다. [독립 검산 결과](clean-baseline.json)"]
    lines += ["", "### 논문 표 4와 대조", "",
              "논문 열은 저자들이 보고한 전체 빌드군 F1입니다. IDA 열은 현재 완료된 입력의 실측 평균입니다. "
              "포트에는 IDA의 디코더와 레지스터 접근 정보가 쓰이므로 기반 디스어셈블러와 특징 추출이 함께 달라집니다."]
    table(lines, ("빌드", "논문 Ghidra", "논문 Ghidra+NSDA", "실측 IDA 기본", "실측 IDA+N5D4 (4바이트 간격)"))
    for name, group in groups.items():
        if group:
            row(lines, name, *(f"{x:.5f}" for x in (*PAPER_F1[name], average(group, "baseline", "f1"),
                                                     average(group, "refined", "f1", "artifact_probes"))))
    lines += ["", "[Neurosymbolic Disassembly, 표 4](https://doi.org/10.1145/3830454.3832592)"]


def main():
    lines = ["# IDA Pro 9.4용 N5D4 평가", ""]
    demo_section(lines)
    corpus_section(lines)
    versions_section(lines)
    lines += ["", "## 실험 방법", "",
              "- 공식 TOML에서 네 Coreutils 빌드의 입력 이름, 기준 주소, 최대 반복 수와 에폭 수를 읽었습니다. "
              "각 stripped ELF의 복사본으로 새 IDB를 열어 자동 분석을 마치고 기본 상태를 측정했습니다. "
              "같은 IDB에 포트를 적용하고 마지막 재분석이 끝난 뒤 다시 채점했습니다.",
              "- 모델은 바이너리별로 새로 학습했습니다. seed 42, 500에폭, 최대 5회, 임계값 0.50을 사용했습니다. "
              "저자 평가 코드의 적용 범위에 맞춰 실행 가능한 세그먼트의 미정의 영역과 기존 데이터 항목을 대상으로 했습니다. "
              "포트의 기본 미리보기에서는 기존 데이터가 제외됩니다.",
              "- CSV의 ground_truth가 0이면 해당 주소부터 4바이트가 정답 코드입니다. "
              "정답은 모델 학습과 IDB 적용이 끝난 후 채점기에만 전달했습니다. "
              "ELF .text의 파일 오프셋으로 IDA 주소를 대응시키고, 각 양성 행의 원시 4바이트와 IDB 값을 대조했습니다. "
              "일치 개수, SHA-256, 장치, 패스별 학습 손실과 경과 시간은 개별 JSON에 있습니다.",
              "- 주 지표는 초기화된 일반 세그먼트에서 IDA가 코드로 표시한 모든 바이트와 정답 집합의 차이로 계산했습니다. "
              "정답 집합 밖의 코드도 FP에 포함했습니다. 보조 지표는 공식 NSDA 함수처럼 블록 시작부터 4바이트 간격으로 검사하고 "
              "데이터·미정의 블록에서 검사한 정답 위치를 FN으로 셉니다. 두 채점기의 분모는 다를 수 있습니다.",
              "- 비교 환경은 Windows, IDA Pro 9.4 (260714), Python 3.14.7, PyTorch 2.15.0 CPU, LTNtorch 1.0.2입니다. "
              "저자 공개값과 로컬 Ghidra 재실행값은 각 표에 표시했습니다. 저자의 Ubuntu/Ghidra 11.3.2/CUDA 환경과 "
              "하드웨어가 달라 실행 시간은 직접 비교하기 어렵습니다.",
              "", f"[공식 설정](https://github.com/gdjs2/NSDA/tree/{ARTIFACT}/configs) · "
              f"[정답 로더](https://github.com/gdjs2/NSDA/blob/{ARTIFACT}/src/DataLoader.py) · "
              f"[NSDA 채점기](https://github.com/gdjs2/NSDA/blob/{ARTIFACT}/src/ltn_helper.py) · "
              f"[고정된 데이터셋](https://github.com/gdjs2/NSDA-coreutils-dataset/tree/{DATASET})", "",
              "## 재실행", "",
              "프로젝트 루트에서 다음과 같이 두 저장소의 평가 자료를 준비합니다.", "",
              "```powershell", "git clone https://github.com/gdjs2/NSDA.git evaluation/upstream/NSDA",
              f"git -C evaluation/upstream/NSDA checkout {ARTIFACT}",
              "git clone https://github.com/gdjs2/NSDA-coreutils-dataset.git evaluation/upstream/coreutils",
              f"git -C evaluation/upstream/coreutils checkout {DATASET}", "```", "",
              "IDA의 idalib를 활성화한 Python으로 프로젝트 루트에서 실행합니다. "
              "학습 워커는 프로젝트의 .venv를 사용합니다.", "", "```powershell",
              "python -X utf8 -u evaluation/benchmark.py",
              "python -X utf8 -u evaluation/benchmark.py --config evaluation/upstream/NSDA/configs/main.toml --output evaluation/full-results --resume",
              "python evaluation/report.py", "```", "",
              "원시 측정값은 [데모 결과](results/)와 [전체 평가 결과](full-results/)에 바이너리별로 저장합니다. "
              "전체 평가의 --build 옵션으로 하나의 아키텍처·컴파일러 조합을 지정할 수 있습니다.", "",
              "Ghidra 비교를 재실행할 때는 프로젝트 가상 환경에 "
              "`pyghidra==2.2.0 rich==14.2.0 loguru==0.7.3`을 추가합니다. 11.3.2는 "
              "`.venv\\Scripts\\python.exe evaluation/ghidra_demo.py --ghidra <Ghidra 설치 폴더>`로 실행합니다. "
              "12.x는 해당 배포본의 Ghidra/Features/PyGhidra/pypkg/dist 안에 있는 pyghidra 휠을 별도 폴더에 풀고 "
              "`--pyghidra-path <휠을 푼 폴더>`를 추가합니다. "
              "IDA 독립 검산은 `python evaluation/clean_baseline.py --ida-dir <IDA 설치 폴더>`로 실행합니다.", "",
              "세 버전의 데모 측정값이 준비되면 Matplotlib을 설치한 Python에서 "
              "`python evaluation/publish_results.py`를 실행해 GitHub README의 결과 표와 그래프를 갱신합니다.", ""]
    (HERE / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
