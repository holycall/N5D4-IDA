"""Run the Coreutils part of an NSDA artifact configuration against fresh IDA databases."""

import argparse
import csv
import hashlib
import json
import platform
import struct
import sys
import tempfile
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent


def metrics(tp, fp, fn):
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else 0,
            "recall": tp / (tp + fn) if tp + fn else 0,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0}


def ground_truth(path):
    # ARMCoreutilsDataLoader and MIPSCoreutilsDataLoader expand a positive word to four bytes.
    truth = set()
    words = []
    with path.open(newline="", encoding="utf-8") as src:
        for row in csv.DictReader(src):
            if row["ground_truth"] == "0":
                start = int(row["address"], 16)
                truth.update(range(start, start + 4))
                words.append((start, bytes.fromhex(row["raw bytes"])))
    if not truth:
        raise ValueError(f"No positive labels in {path}")
    return truth, words


def address_mapping(image, base):
    # Map ELF VAs using the loader's file mapping for .text, independently of the labels.
    import ida_loader
    import ida_idaapi
    if image[:5] != b"\x7fELF\x01":
        raise ValueError("Expected a 32-bit ELF")
    order = "<" if image[5] == 1 else ">"
    header = struct.unpack_from(order + "HHIIIIIHHHHHH", image, 16)
    _, _, _, _, phoff, shoff, _, _, phsize, phnum, shsize, shnum, shstr = header
    programs = [struct.unpack_from(order + "8I", image, phoff + i * phsize) for i in range(phnum)]
    loads = [p for p in programs if p[0] == 1]
    sections = [struct.unpack_from(order + "10I", image, shoff + i * shsize) for i in range(shnum)]
    strings = sections[shstr][4]
    text = next(s for s in sections if image.startswith(b".text\0", strings + s[0]))
    ida_text = ida_loader.get_fileregion_ea(text[4])
    if ida_text == ida_idaapi.BADADDR:
        raise ValueError("IDA has no .text file mapping")
    link_base = min(p[2] - p[1] for p in loads if p[1] == 0)
    return text[3] + base - link_base - ida_text


def score(blocks, delta, truth):
    code, positive_probe, negative_probe = set(), set(), set()
    for block in blocks:
        lo, hi = block.start + delta, block.end + delta
        # The upstream NSDA scorer steps by four, with the inclusive end as a Python stop.
        probes = range(lo, hi - 1, 4)
        if block.kind == "Code":
            code.update(range(lo, hi))
            positive_probe.update(probes)
        else:
            negative_probe.update(probes)
    return {"bytes": metrics(len(code & truth), len(code - truth), len(truth - code)),
            "artifact_probes": metrics(len(positive_probe & truth), len(positive_probe - truth),
                                       len(negative_probe & truth))}


def evaluate(binary, labels, settings, limits):
    import idapro
    import ida_bytes
    if str(HERE.parent) not in sys.path:
        sys.path.insert(0, str(HERE.parent))
    import N5D4
    noop = lambda msg: None
    image = binary.read_bytes()
    with tempfile.TemporaryDirectory(prefix="n5d4-eval-") as dirname:
        local = Path(dirname) / "sample.elf"
        local.write_bytes(image)
        begin = time.monotonic()
        if idapro.open_database(str(local), True):
            raise RuntimeError(f"IDA could not open {binary}")
        try:
            analyzed = time.monotonic()
            delta = address_mapping(image, settings["base"])
            before = N5D4.collect(noop)
            messages = []
            opts = N5D4.Options(apply=True, include_data=True,
                                epochs=limits["epoches_limit"], passes=limits["iteration_limit"])
            started = time.monotonic()
            rows = N5D4.run(opts, log=messages.append)
            finished = time.monotonic()
            after = N5D4.collect(noop)
            # Neither the training worker nor IDA receives labels before refinement is complete.
            truth, words = ground_truth(labels)
            matched = sum(ida_bytes.get_bytes(addr - delta, 4, 0) == raw for addr, raw in words)
            if matched < 0.99 * len(words):
                raise ValueError(f"CSV-to-IDB mapping mismatch: only {matched}/{len(words)} positive words match")
            return {"binary": binary.name, "sha256": hashlib.sha256(image).hexdigest(),
                    "labels_sha256": hashlib.sha256(labels.read_bytes()).hexdigest(),
                    "ida_version": idapro.get_library_version(), "ida_to_label_delta": delta,
                    "positive_words": len(words), "matching_code_words": matched,
                    "baseline": score(before, delta, truth), "refined": score(after, delta, truth),
                    "applied_blocks": len(rows), "messages": messages,
                    "initial_analysis_seconds": round(analyzed - begin, 3),
                    "refinement_seconds": round(finished - started, 3)}
        finally:
            idapro.close_database(False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=HERE / "upstream/NSDA/configs/demo.toml")
    parser.add_argument("--dataset", type=Path, default=HERE / "upstream/coreutils")
    parser.add_argument("--output", type=Path, default=HERE / "results")
    parser.add_argument("--build", help="Restrict to one architecture/compiler directory")
    parser.add_argument("--resume", action="store_true", help="Reuse matching completed measurements")
    args = parser.parse_args()
    config = tomllib.loads(args.config.resolve().read_text(encoding="utf-8"))
    dataset, output = args.dataset.resolve(), args.output.resolve()
    output.mkdir(exist_ok=True, parents=True)
    implementation = hashlib.sha256((HERE.parent / "N5D4.py").read_bytes()
                                    + (HERE.parent / "n5d4_train.py").read_bytes()
                                    + Path(__file__).read_bytes()).hexdigest()
    failures = []
    for name in config["config"]["datasets"]:
        if "coreutils" not in name:
            continue
        settings = config["dataset"][name]
        build = Path(settings["path"]).name
        if args.build and args.build != build:
            continue
        root = dataset / build
        paths = root / "stripped/usr/local/bin"
        names = settings["subset"] if config["config"]["eval_type"] == "Subset Evaluation" else [
            p.stem for p in sorted((root / "labels").glob("*.csv"))]
        if not names:
            raise ValueError(f"No samples in {root}")
        for binary in names:
            source = paths / binary
            label = root / "labels" / (binary + ".csv")
            dest = output / build / (binary + ".json")
            signature = {"implementation_sha256": implementation, "platform": platform.platform(),
                         "base": settings["base"], "limits": config["evaluator"]["nsda"],
                         "binary_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                         "csv_sha256": hashlib.sha256(label.read_bytes()).hexdigest()}
            if args.resume and dest.is_file():
                saved = json.loads(dest.read_text(encoding="utf-8"))
                if saved.get("run_signature") == signature and "refined" in saved:
                    continue
            print(f"{build}/{binary}", flush=True)
            try:
                result = evaluate(source, label, settings, config["evaluator"]["nsda"])
            except Exception as exc:
                failures.append(f"{build}/{binary}: {exc}")
                print(f"FAILED {failures[-1]}", flush=True)
                continue
            result["run_signature"] = signature
            result["build"] = build
            result["artifact_config"] = args.config.name
            dest.parent.mkdir(exist_ok=True)
            temp = dest.with_suffix(".tmp")
            temp.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            temp.replace(dest)
            print(f"byte F1 {result['baseline']['bytes']['f1']:.5f} -> "
                  f"{result['refined']['bytes']['f1']:.5f}; {result['applied_blocks']} blocks", flush=True)
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
