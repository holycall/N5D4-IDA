"""Independently measure IDA's initial listing in an empty IDAUSR profile."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def measure(root):
    import idapro
    import ida_bytes
    import ida_segment
    import idautils
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    from benchmark import address_mapping, ground_truth, metrics

    results = {}
    for variant, base in (("arm32-gcc", 65536), ("arm32-llvm", 0),
                          ("mips-gcc", 4194304), ("mips-llvm", 0)):
        folder = HERE / "upstream/coreutils" / variant
        group = results[variant] = {}
        for label in sorted((folder / "labels").glob("*.csv")):
            binary = folder / "stripped/usr/local/bin" / label.stem
            with tempfile.TemporaryDirectory(dir=root) as work:
                target = Path(work) / "sample.elf"
                shutil.copyfile(binary, target)
                if idapro.open_database(str(target), True):
                    raise RuntimeError(f"Could not open {binary}")
                try:
                    slide = address_mapping(target.read_bytes(), base)
                    predicted = set()
                    for start in idautils.Segments():
                        seg = ida_segment.getseg(start)
                        if ida_segment.is_spec_segm(seg.type) or ida_bytes.nbits(start) != 8:
                            continue
                        for ea in idautils.Heads(start, seg.end_ea):
                            if ida_bytes.is_code(ida_bytes.get_full_flags(ea)) and ida_bytes.is_loaded(ea):
                                predicted.update(range(ea + slide, ida_bytes.get_item_end(ea) + slide))
                    truth, _ = ground_truth(label)
                    group[label.stem] = metrics(len(predicted & truth), len(predicted - truth),
                                                len(truth - predicted))
                finally:
                    idapro.close_database(False)
            dest = HERE / "clean-baseline.json"
            tmp = dest.with_suffix(".tmp")
            tmp.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
            tmp.replace(dest)
        print(f"{variant}: {len(group)} isolated baseline measurements", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--ida-dir", type=Path, help="IDA installation to use in the isolated profile")
    args = parser.parse_args()
    if args.work:
        measure(args.work)
    else:
        with tempfile.TemporaryDirectory(prefix="ida-clean-") as work:
            profile = Path(work) / "profile"
            profile.mkdir()
            env = dict(os.environ, IDAUSR=str(profile))
            if args.ida_dir:
                env["IDADIR"] = str(args.ida_dir.resolve())
            subprocess.run([sys.executable, "-u", str(Path(__file__).resolve()), "--work", work],
                           env=env, check=True)
