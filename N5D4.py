"""Neurosymbolic disassembly refinement for IDA Pro. Run via File > Script file."""

import bisect
import json
import math
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import ida_auto
import ida_bytes
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_segment
import ida_ua
import ida_undo
import idautils

ROOT = Path(__file__).resolve().parent
BADADDR = ida_idaapi.BADADDR
PRINTABLE = re.compile(b"[ -~]+")
ARITHMETIC = re.compile(
    r"^(?:v?(?:add|sub|mul|div)|i(?:mul|div)|[su](?:div|mull?)|"
    r"d(?:add|sub)|adc|sbb|sbc|rsb|mla|mls|madd|msub|inc|dec)"
)
COMPARE = re.compile(r"^(?:v?cmp|cmn|test|tst|teq|slt|slti|comis|ucomis)")


class Cancelled(Exception):
    pass


def progress(message):
    ida_kernwin.replace_wait_box(message)
    if ida_kernwin.user_cancelled():
        raise Cancelled()


@dataclass
class Options:
    apply: bool = False
    include_data: bool = False
    all_segments: bool = False
    passes: int = 5
    epochs: int = 500
    threshold: float = 0.50


@dataclass
class Block:
    start: int
    end: int                     # exclusive
    kind: str
    segment: int
    executable: bool
    features: list
    conditional_compare: object  # True, False, or None for a non-conditional end
    high_zero: bool
    long_printable: bool
    failed: bool
    falls_through: bool
    targets: set


def loaded_ranges(seg, tick):
    """Coalesce initialized bytes, including initialized islands inside sparse segments."""
    ea = seg.start_ea
    start = None
    while ea < seg.end_ea:
        tick(f"Reading initialized ranges at {ea:#x}")
        if not ida_bytes.is_loaded(ea):
            if start is not None:
                yield start, ea
                start = None
            ea = ida_bytes.next_inited(ea, seg.end_ea)
            if ea == BADADDR:
                break
        length = min(65536, seg.end_ea - ea)
        result = ida_bytes.get_bytes_and_mask(ea, length)
        if result is None:
            raise RuntimeError(f"Cannot read IDB bytes at {ea:#x}")
        _, mask = result
        bits = int.from_bytes(mask, "little") & ((1 << length) - 1)
        if bits.bit_count() == length:
            if start is None:
                start = ea
            ea += length
            continue
        # A partial page starts at a loaded byte. Skip each hole with next_inited.
        count = (bits ^ (bits + 1)).bit_length() - 1
        if not count:
            raise RuntimeError(f"Inconsistent IDB byte mask at {ea:#x}")
        yield ea if start is None else start, ea + count
        start = None
        ea += count
    if start is not None:
        yield start, seg.end_ea


def item_kind(ea):
    flags = ida_bytes.get_full_flags(ida_bytes.get_item_head(ea))
    if ida_bytes.is_code(flags):
        return "Code"
    return "Data" if ida_bytes.is_data(flags) else "Unknown"


def item_runs(start, end, tick):
    run_start = ea = start
    kind = item_kind(ea)
    items = 0
    while ea < end:
        if items % 4096 == 0:
            tick(f"Reading IDA items at {ea:#x}")
        current = item_kind(ea)
        if current != kind:
            yield run_start, ea, kind
            run_start, kind = ea, current
        if current == "Unknown":
            ea = min(end, ida_bytes.next_head(ea, end))
        else:
            ea = min(end, ida_bytes.get_item_end(ea))
        items += 1
    yield run_start, end, kind


def register_access(insn, feature):
    accesses = ida_idp.reg_accesses_t()
    if ida_idp.ph_get_reg_accesses(accesses, insn, 0) > 0:
        return ({a.regnum for a in accesses if a.access_type & ida_idp.READ_ACCESS},
                {a.regnum for a in accesses if a.access_type & ida_idp.WRITE_ACCESS})
    reads, writes = set(), set()
    for op in insn.ops:
        if op.type == ida_ua.o_void:
            break
        if op.type == ida_ua.o_reg:
            if ida_idp.has_cf_use(feature, op.n):
                reads.add(op.reg)
            if ida_idp.has_cf_chg(feature, op.n):
                writes.add(op.reg)
    return reads, writes


@dataclass
class Stats:
    count: int = 0
    constants: int = 0
    strings: int = 0
    transfers: int = 0
    calls: int = 0
    arithmetic: int = 0
    def_use: int = 0
    compared: bool = False
    conditional_compare: object = None
    failed: bool = False
    falls_through: bool = False
    targets: set = field(default_factory=set)
    definitions: dict = field(default_factory=dict)

    def observe(self, insn, kind):
        feature = insn.get_canon_feature()
        mnemonic = insn.get_canon_mnem().lower()
        is_call = ida_idp.is_call_insn(insn)
        is_ret = ida_idp.is_ret_insn(insn)
        direct = any(op.type in (ida_ua.o_near, ida_ua.o_far) for op in insn.ops)
        known_targets = set(idautils.CodeRefsFrom(insn.ea, False)) if kind == "Code" else set()
        transfer = bool(is_call or is_ret or direct or known_targets or
                        feature & (ida_idp.CF_STOP | ida_idp.CF_JUMP) or
                        ida_idp.is_indirect_jump_insn(insn))
        conditional = False
        if transfer and not is_call and not is_ret:
            cond = ida_idp.get_ph().is_cond_insn(insn)
            conditional = cond == 1 or (cond == 0 and direct and not feature & ida_idp.CF_STOP)
        self.conditional_compare = self.compared if conditional else None
        self.compared |= bool(COMPARE.match(mnemonic))
        self.falls_through = bool(conditional or (not is_ret and not feature & ida_idp.CF_STOP))
        if kind == "Code":
            # IDA records non-returning calls and architecture-specific flow in the IDB.
            # For a successor that IDA has not decoded yet, keep the semantic estimate.
            successor = insn.ea + insn.size
            if ida_bytes.is_code(ida_bytes.get_full_flags(successor)):
                self.falls_through = successor in idautils.CodeRefsFrom(insn.ea, True) and (
                    ida_bytes.is_flow(ida_bytes.get_full_flags(successor)))
            self.targets.update(known_targets)
        self.calls += int(is_call)
        self.transfers += int(transfer)
        self.arithmetic += int(bool(ARITHMETIC.match(mnemonic)))
        self.strings += sum(ida_bytes.is_strlit(ida_bytes.get_full_flags(ida_bytes.get_item_head(target)))
                            for target in idautils.DataRefsFrom(insn.ea))
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            if op.type in (ida_ua.o_imm, ida_ua.o_displ, ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                self.constants += 1
        reads, writes = register_access(insn, feature)
        self.def_use += sum(self.count - self.definitions[reg] <= 16
                            for reg in reads if reg in self.definitions)
        self.definitions.update((reg, self.count) for reg in writes)
        self.count += 1
        return transfer

    def block(self, start, end, kind, seg):
        size = end - start
        data = ida_bytes.get_bytes(start, size, 0)
        if data is None or len(data) != size:
            raise RuntimeError(f"Cannot read complete block at {start:#x}")
        zero = data.count(0)
        printable = longest = 0
        for match in PRINTABLE.finditer(data):
            length = match.end() - match.start()
            printable += length
            longest = max(longest, length)
        counts = [self.strings, self.constants, self.transfers, self.calls, self.count,
                  self.arithmetic, zero, self.def_use, printable]
        executable = bool(seg.perm & ida_segment.SEGPERM_EXEC) or (
            seg.perm == 0 and seg.type == ida_segment.SEG_CODE)
        return Block(start, end, kind, seg.start_ea, executable,
                     [n / size for n in counts], self.conditional_compare, 2 * zero >= size,
                     2 * longest >= size, self.failed, self.falls_through, self.targets)


def scan_run(start, end, kind, seg, tick):
    stats = Stats()
    ea = block_start = start
    steps = 0
    while ea < end:
        if steps % 2048 == 0:
            tick(f"Decoding {kind} at {ea:#x}")
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        valid = 0 < size <= end - ea
        if kind == "Code":
            item_end = min(end, ida_bytes.get_item_end(ea))
            valid = valid and ea == ida_bytes.get_item_head(ea) and ea + size == item_end
        if valid:
            ea += size
            if stats.observe(insn, kind):
                yield stats.block(block_start, ea, kind, seg)
                block_start, stats = ea, Stats()
        else:
            stats.failed = True
            stats.falls_through = False
            stats.conditional_compare = None
            ea = item_end if kind == "Code" else ea + 1
        steps += 1
    if block_start < end:
        yield stats.block(block_start, end, kind, seg)


def collect(tick):
    blocks = []
    for base in idautils.Segments():
        seg = ida_segment.getseg(base)
        if ida_segment.is_spec_segm(seg.type) or ida_bytes.nbits(base) != 8:
            continue
        for start, end in loaded_ranges(seg, tick):
            for lo, hi, kind in item_runs(start, end, tick):
                blocks.extend(scan_run(lo, hi, kind, seg, tick))
    return blocks


def training_data(blocks):
    starts = [b.start for b in blocks]
    transfers, fallthrough = set(), set()
    for i, block in enumerate(blocks):
        for target in block.targets:
            j = bisect.bisect_right(starts, target) - 1
            if j >= 0 and target < blocks[j].end:
                transfers.add((i, j))
        if i + 1 < len(blocks):
            nxt = blocks[i + 1]
            if block.falls_through and block.end == nxt.start and block.segment == nxt.segment:
                fallthrough.add((i, i + 1))
    unary = [[] for _ in range(7)]
    for i, block in enumerate(blocks):
        matches = (block.kind == "Code", block.kind == "Data",
                   block.conditional_compare is True, block.conditional_compare is False,
                   block.high_zero, block.long_printable, block.failed)
        for group, matched in zip(unary, matches):
            if matched:
                group.append(i)
    return {"features": [block.features for block in blocks],
            "unary": list(zip((True, False, True, False, False, False, False), unary)),
            "fallthrough": sorted(fallthrough - transfers), "transfer": sorted(transfers)}


def worker_python():
    configured = os.environ.get("N5D4_PYTHON")
    path = Path(configured) if configured else ROOT / ".venv" / (
        "Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not path.is_file():
        raise RuntimeError(f"Training Python not found at {path}. See README.md or set N5D4_PYTHON.")
    return path.resolve()


def predict(blocks, folder, epochs, tick):
    with (folder / "features.json").open("w", encoding="utf-8") as stream:
        json.dump(training_data(blocks), stream, separators=(",", ":"))
    args = [str(worker_python()), "-I", str(ROOT / "n5d4_train.py"), str(folder), str(epochs)]
    with (folder / "worker.log").open("wb") as log:
        worker = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            while worker.poll() is None:
                tick(f"Training the code classifier ({epochs} epochs maximum)")
                try:
                    worker.wait(timeout=0.20)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if worker.poll() is None:
                worker.kill()
                worker.wait()
    if worker.returncode:
        output = (folder / "worker.log").read_text(encoding="utf-8", errors="replace")
        raise RuntimeError(f"Training worker exited with {worker.returncode}\n{output[-3000:]}")
    return json.loads((folder / "result.json").read_text(encoding="utf-8"))


def candidate(block, options):
    if block.failed or not (block.executable or options.all_segments):
        return False
    if block.kind == "Data":
        # Undefining a tail destroys the entire original IDA item.
        return (options.include_data and ida_bytes.get_item_head(block.start) == block.start
                and ida_bytes.get_item_end(block.end - 1) == block.end)
    return block.kind == "Unknown"


def plan_block(block):
    # Re-check IDB ownership and decoder boundaries immediately before editing.
    ea = block.start
    while ea < block.end:
        if item_kind(ea) != block.kind or ida_bytes.get_item_head(ea) != ea:
            return []
        if block.kind == "Unknown":
            if ida_bytes.next_head(ea, block.end) < block.end:
                return []
            break
        ea = ida_bytes.get_item_end(ea)
        if ea > block.end:
            return []
    plan = []
    ea = block.start
    while ea < block.end:
        size = ida_ua.decode_insn(ida_ua.insn_t(), ea)
        if not 0 < size <= block.end - ea:
            return []
        plan.append((ea, size))
        ea += size
    return plan


def apply_pass(candidates, tick):
    applied = []
    checkpoint = False
    try:
        for block, score in candidates:
            tick(f"Applying block at {block.start:#x}")
            plan = plan_block(block)
            if not plan:
                continue
            if not checkpoint:
                if not ida_undo.create_undo_point("N5D4", "N5D4 refinement pass"):
                    raise RuntimeError("Enable IDA undo history to apply a recoverable pass.")
                checkpoint = True
            old = ida_bytes.get_cmt(block.start, False) or ""
            if block.kind == "Data":
                if not ida_bytes.del_items(block.start, ida_bytes.DELIT_SIMPLE, block.end - block.start):
                    raise RuntimeError(f"IDA could not undefine data at {block.start:#x}")
            for ea, size in plan:
                if ida_ua.create_insn(ea) != size:
                    raise RuntimeError(f"IDA could not create the expected instruction at {ea:#x}")
            note = f"N5D4 code score {score:.3f} (previously {block.kind})"
            if not ida_bytes.set_cmt(block.start, "\n".join(filter(None, (old, note))), False):
                raise RuntimeError(f"IDA could not annotate {block.start:#x}")
            ida_auto.plan_range(block.start, block.end)
            applied.append((block, score))
        if applied and not ida_auto.auto_wait():
            raise Cancelled()
    except BaseException:
        if checkpoint and not ida_undo.perform_undo():
            raise RuntimeError("IDA failed to roll back the current pass. Inspect the database before saving.")
        raise
    return applied


def run(options, tick=lambda message: None, log=print):
    if options.epochs < 1 or options.passes < 1 or not 0 <= options.threshold <= 1:
        raise ValueError("Passes and epochs must be positive. The threshold must be between 0 and 1.")
    worker_python()
    if not ida_auto.auto_wait():
        raise Cancelled()
    results = []
    with tempfile.TemporaryDirectory(prefix="n5d4-") as tmp:
        for iteration in range(1, (options.passes if options.apply else 1) + 1):
            blocks = collect(tick)
            eligible = [i for i, block in enumerate(blocks) if candidate(block, options)]
            log(f"Pass {iteration}: {len(blocks)} blocks, {len(eligible)} eligible.")
            if not eligible:
                break
            prediction = predict(blocks, Path(tmp), options.epochs, tick)
            if "reason" in prediction:
                log(prediction["reason"])
                break
            scores = prediction["scores"]
            if len(scores) != len(blocks) or not all(math.isfinite(s) and 0 <= s <= 1 for s in scores):
                raise RuntimeError("Invalid prediction count or score from training worker.")
            selected = [(blocks[i], scores[i]) for i in eligible if scores[i] >= options.threshold]
            log(f"Pass {iteration}: {prediction['device']}, {prediction['epochs']} epochs, "
                f"loss {prediction['loss']:.4f}, {len(selected)} candidates at or above threshold.")
            rows = apply_pass(selected, tick) if options.apply else selected
            results.extend(rows)
            if options.apply:
                log(f"Pass {iteration}: {len(rows)} blocks converted.")
            if not rows:
                break
    return results


def settings_form():
    form = ida_kernwin.Form
    return form("""STARTITEM 0
BUTTON YES* Run
N5D4 disassembly refinement

<##Mode##Preview candidates:{preview}>
<Apply to database:{apply}>{mode}>

<##Candidate scope##Include defined data (whole IDA items only):{data}>
<Include segments without execute permission:{allsegs}>{scope}>

<Minimum code score (percent):{threshold}>
<Training epochs per pass:{epochs}>
<Maximum passes in Apply mode:{passes}>
""", {
        "mode": form.RadGroupControl(("preview", "apply")),
        "scope": form.ChkGroupControl(("data", "allsegs")),
        "threshold": form.NumericInput(tp=form.FT_DEC, value=50),
        "epochs": form.NumericInput(tp=form.FT_DEC, value=500),
        "passes": form.NumericInput(tp=form.FT_DEC, value=5),
    })


class Results(ida_kernwin.Choose):
    def __init__(self, rows, applied):
        title = "N5D4 applied blocks" if applied else "N5D4 candidate blocks"
        super().__init__(title, [["Start", 18], ["End (exclusive)", 18], ["Bytes", 8],
                                 ["Original type", 12], ["Code score", 10]])
        self.rows = sorted(rows, key=lambda row: (-row[1], row[0].start))

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, index):
        block, score = self.rows[index]
        return [f"{block.start:X}", f"{block.end:X}", str(block.end - block.start),
                block.kind, f"{score:.4f}"]

    def OnSelectLine(self, index):
        ida_kernwin.jumpto(self.rows[index][0].start)
        return (self.NOTHING_CHANGED,)


def main():
    form = settings_form()
    form.Compile()
    try:
        if form.Execute() != 1:
            return
        options = Options(apply=bool(form.mode.value), include_data=bool(form.scope.value & 1),
                          all_segments=bool(form.scope.value & 2), passes=form.passes.value,
                          epochs=form.epochs.value, threshold=form.threshold.value / 100.0)
    finally:
        form.Free()
    last = 0.0

    def tick(message):
        nonlocal last
        now = time.monotonic()
        if now - last > 0.15:
            progress(message)
            last = now

    ida_kernwin.show_wait_box("Waiting for IDA auto-analysis")
    try:
        rows = run(options, tick, lambda msg: ida_kernwin.msg(f"[N5D4] {msg}\n"))
    except Cancelled:
        ida_kernwin.msg("[N5D4] Cancelled. Completed passes are retained.\n")
        return
    except Exception as exc:
        ida_kernwin.warning(f"N5D4: {exc}")
        return
    finally:
        ida_kernwin.hide_wait_box()
    if rows:
        chooser = Results(rows, options.apply)
        chooser.Close()  # Replace the previous result set for this mode.
        chooser.Show()
    else:
        ida_kernwin.msg("[N5D4] No blocks to display.\n")


class N5D4Module(ida_idaapi.plugmod_t):
    def run(self, arg):
        main()
        return True


class N5D4Plugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Refine code and data boundaries with a Logic Tensor Network"
    help = ""
    wanted_name = "N5D4 disassembly refinement"
    wanted_hotkey = ""

    def init(self):
        return N5D4Module()


def PLUGIN_ENTRY():
    return N5D4Plugin()


if __name__ == "__main__":
    main()
