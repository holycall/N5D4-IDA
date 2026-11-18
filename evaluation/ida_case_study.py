"""Inspect the switch in paper section 5.6 before applying any refinement."""

import idapro

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

import ida_bytes
import ida_nalt
import ida_xref
import idautils


def main():
    here = Path(__file__).resolve().parent
    source = here / "upstream/coreutils/arm32-gcc/stripped/usr/local/bin/base64"
    with tempfile.TemporaryDirectory(prefix="nsda-switch-") as folder:
        local = Path(folder) / "base64.elf"
        shutil.copyfile(source, local)
        if idapro.open_database(str(local), True):
            raise RuntimeError("Cannot load the ARM32 GCC demo binary")
        try:
            dispatch = 0x15C74
            info = ida_nalt.get_switch_info(dispatch)
            results = {"sha256": hashlib.sha256(local.read_bytes()).hexdigest(),
                       "ida_version": idapro.get_library_version(), "dispatch": hex(dispatch),
                       "recognized": info is not None, "table": None, "cases": [],
                       "paper_targets": []}
            if info is not None:
                results["table"] = hex(info.jumps)
                cases = ida_xref.calc_switch_cases(dispatch, info)
                if cases:
                    results["cases"] = [[list(values), hex(target)]
                                        for values, target in zip(cases.cases, cases.targets)]
            for index in (1, 2, 3):
                slot = 0x15c7c + 4 * index
                target = ida_bytes.get_dword(slot)
                results["paper_targets"].append({
                    "index": index, "slot": hex(slot), "target": hex(target),
                    "code_head": ida_bytes.is_code(ida_bytes.get_full_flags(target)),
                    "xref_from_dispatch": dispatch in idautils.CodeRefsTo(target, False)})
            out = here / "vanilla-ida-switch.json"
            out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(results))
        finally:
            idapro.close_database(False)


if __name__ == "__main__":
    main()
