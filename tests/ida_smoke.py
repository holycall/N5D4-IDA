"""Run with a Python configured for idalib. Only temporary raw binaries/IDBs are used."""

import idapro

import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import ida_auto
import ida_bytes
import ida_ua
import ida_undo

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import N5D4 as n


def nop(message):
    pass


def check(database):
    unit = bytes.fromhex("31 c0 83 c0 01 c3")  # xor ax,ax / add ax,1 / ret
    data = unit * 2 + bytes(24)
    database.write_bytes(data)
    assert idapro.open_database(str(database), False, "-TBinary -pmetapc") == 0
    try:
        assert ida_auto.auto_wait()
        assert ida_bytes.del_items(0, ida_bytes.DELIT_SIMPLE, len(data))
        for ea, size in [(0, 2), (2, 3), (5, 1)]:
            assert ida_ua.create_insn(ea) == size
        assert ida_bytes.create_byte(12, 24)
        assert ida_auto.auto_wait()
        options = n.Options(epochs=500, all_segments=True)
        blocks = n.collect(nop)
        assert [(b.start, b.end, b.kind) for b in blocks] == [
            (0, 6, "Code"), (6, 12, "Unknown"), (12, 36, "Data")], blocks
        assert blocks[0].features == blocks[1].features
        assert blocks[0].features[7] > 0 and blocks[2].high_zero
        form = n.settings_form()
        form.Compile()
        try:
            assert (form.mode.value, form.scope.value, form.epochs.value) == (0, 0, 500)
        finally:
            form.Free()
        rows = n.run(options)
        assert [b.start for b, _ in rows] == [6], rows
        assert n.item_kind(6) == "Unknown" and ida_bytes.get_cmt(6, False) is None
        assert n.Results(rows, False).OnGetLine(0)[0] == "6"
        options.apply = True
        assert ida_bytes.set_cmt(6, "reviewer note", False)
        applied = n.run(options)
        assert [(b.start, s) for b, s in applied] == [(b.start, s) for b, s in rows]
        assert all(ida_bytes.is_code(ida_bytes.get_full_flags(ea)) for ea in (6, 8, 11))
        assert "reviewer note" in ida_bytes.get_cmt(6, False) and "N5D4" in ida_bytes.get_cmt(6, False)
        assert ida_bytes.get_item_end(12) == 36 and ida_bytes.get_bytes(0, 36) == data
        assert not n.run(options)
        assert ida_undo.perform_undo()
        assert n.item_kind(6) == "Unknown" and ida_bytes.get_cmt(6, False) == "reviewer note"

        assert ida_bytes.create_byte(6, 6)
        b = next(b for b in n.collect(nop) if b.start == 6)
        assert not n.candidate(b, options)
        options.include_data = True
        assert n.candidate(b, options)
        create = ida_ua.create_insn
        with patch.object(ida_ua, "create_insn", side_effect=lambda ea: 0 if ea == 8 else create(ea)):
            try:
                n.apply_pass([(b, 0.75)], nop)
            except RuntimeError as exc:
                assert "expected instruction" in str(exc), exc
            else:
                raise AssertionError("Partial conversion was accepted")
        assert n.item_kind(6) == "Data" and ida_bytes.get_item_end(6) == 12
        assert n.apply_pass([(b, 0.75)], nop)
        assert n.item_kind(6) == "Code" and n.item_kind(12) == "Data"
        print(f"Recovered [{6:#x}, {12:#x}) at score {rows[0][1]:.4f}. Undo and rollback passed.")
    finally:
        idapro.close_database(False)


def check_flow(database):
    # cmp ax,1 / jz next-ret / nop / ret / jnz start / ret
    database.write_bytes(bytes.fromhex("83 f8 01 74 01 90 c3 75 f7 c3"))
    assert idapro.open_database(str(database), False, "-TBinary -pmetapc") == 0
    try:
        blocks = n.collect(nop)
        assert [(b.start, b.end) for b in blocks] == [(0, 5), (5, 7), (7, 9), (9, 10)]
        assert [b.conditional_compare for b in blocks] == [True, None, False, None]
        assert n.training_data(blocks)["fallthrough"] == [(0, 1), (2, 3)]
        assert ida_bytes.create_byte(0, 10)
        for block in n.collect(nop):
            assert not n.candidate(block, n.Options(include_data=True, all_segments=True))
    finally:
        idapro.close_database(False)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="n5d4-test-") as folder:
        check(Path(folder) / "sample.bin")
        check_flow(Path(folder) / "branches.bin")
