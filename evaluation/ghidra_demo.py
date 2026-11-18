"""Re-run the authors' two legacy Ghidra evaluators on the four Coreutils demo inputs."""

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--pyghidra-path", type=Path,
                        help="Directory containing the PyGhidra package matching this release")
    args = parser.parse_args()
    if args.pyghidra_path:
        sys.path.insert(0, str(args.pyghidra_path.resolve()))
    import pyghidra
    import torch
    from loguru import logger
    from importlib.metadata import version

    ghidra = args.ghidra.resolve()
    artifact = HERE / "upstream/NSDA"
    config = tomllib.loads((artifact / "configs/demo.toml").read_text(encoding="utf-8"))
    torch.set_num_threads(2)
    logger.remove()
    logger.add(sys.stderr, level="WARNING")
    # The upstream evaluator imports Java classes at module import time.
    pyghidra.start(install_dir=ghidra)
    from ghidra.framework import Application
    sys.path.insert(0, str(artifact / "src"))
    from DataLoader import ARMCoreutilsDataLoader, MIPSCoreutilsDataLoader
    from Evaluator import GhidraEvaluator, NSDAEvaluator

    release = str(Application.getApplicationVersion())
    if int(release.split(".")[0]) >= 12:
        config["evaluator"] = tomllib.loads((artifact / "configs/main-12.toml").read_text(
            encoding="utf-8"))["evaluator"]
    out = HERE / "ghidra-results" / release
    out.mkdir(exist_ok=True, parents=True)
    for name in config["config"]["datasets"]:
        if "coreutils" not in name:
            continue
        spec = config["dataset"][name]
        build = Path(spec["path"]).name
        source = HERE / "upstream/coreutils" / build
        with tempfile.TemporaryDirectory(prefix="nsda-demo-") as folder:
            view = Path(folder)
            for binary in spec["subset"]:
                for rel in (Path("stripped/usr/local/bin") / binary, Path("labels") / (binary + ".csv")):
                    (view / rel.parent).mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source / rel, view / rel)
            loader = ARMCoreutilsDataLoader() if build.startswith("arm32") else MIPSCoreutilsDataLoader()
            for sample in loader.load(str(view)).values():
                sha = hashlib.sha256(Path(sample.binary_path).read_bytes()).hexdigest()
                for key, evaluator in (("ghidra", GhidraEvaluator()), ("nsda", NSDAEvaluator())):
                    dest = out / f"{build}-{sample.name}-{key}.json"
                    print(f"{build}/{sample.name}  {key}", flush=True)
                    start = time.monotonic()
                    torch.manual_seed(42)
                    p, r, pre, train, post, _, _ = evaluator.evaluate(
                        binary_path=sample.binary_path, base=spec["base"], language=spec["language"],
                        code_set=sample.code_set, spinner=None, args=config["evaluator"][key])
                    result = {"build": build, "binary": sample.name, "evaluator": key,
                              "ghidra": str(Application.getApplicationVersion()), "seed": 42,
                              "sha256": sha, "python": sys.version, "pyghidra": version("pyghidra"),
                              "torch": torch.__version__, "ltntorch": version("LTNtorch"),
                              "precision": p, "recall": r, "f1": 2*p*r/(p+r) if p+r else 0,
                              "preprocessing_seconds": pre, "training_seconds": train,
                              "postprocessing_seconds": post, "wall_seconds": time.monotonic() - start}
                    dest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
                    print(f"F1 {result['f1']:.6f}", flush=True)


if __name__ == "__main__":
    main()
