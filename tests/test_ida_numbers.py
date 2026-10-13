"""Check parsed numbers against IDA's own operand values on real databases.

Skipped unless idapro can load an IDA install and IDA_COLORS_IDBS names a directory of .i64 files.
"""

import os
from pathlib import Path

import pytest

from ida_colors.color_parser import parse_full
from ida_colors.numbers import numbers

# idapro raises a plain ImportError when it can't find an IDA install.
idapro = pytest.importorskip('idapro', exc_type=ImportError)
import ida_auto  # noqa: E402
import ida_bytes  # noqa: E402
import ida_lines  # noqa: E402
import ida_ua  # noqa: E402
import idautils  # noqa: E402

IDBS_DIR = os.environ.get('IDA_COLORS_IDBS')
IDBS = sorted(Path(IDBS_DIR).glob('*.i64')) if IDBS_DIR else []


@pytest.mark.skipif(not IDBS, reason='set IDA_COLORS_IDBS to a directory of .i64 files')
@pytest.mark.parametrize('idb_copy', IDBS, ids=lambda p: p.stem, indirect=True)
def test_numbers_agree_with_operand_values(idb_copy: Path) -> None:
    assert idapro.open_database(str(idb_copy), False) == 0
    try:
        ida_auto.auto_wait()
        checked = 0
        disagreements = []
        for ea in idautils.Heads():
            if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                continue
            line = ida_lines.generate_disasm_line(ea, 0)
            insn = idautils.DecodeInstruction(ea)
            assert insn is not None
            for number in numbers(parse_full(line)):
                if not number.standalone or number.operand is None:
                    continue
                op = insn.ops[number.operand - 1]
                if op.type != ida_ua.o_imm:
                    continue
                # IDA sign-extends op.value to 64 bits but prints the immediate at the operand's width, e.g.
                # `mov esi, 0FFFFFFFFh` has op.value 0xFFFFFFFFFFFFFFFF. Compare at that width.
                mask = (1 << 8 * ida_ua.get_dtype_size(op.dtype)) - 1
                checked += 1
                if number.value & mask != op.value & mask:
                    disagreements.append((hex(ea), ida_lines.tag_remove(line), number, hex(op.value)))
        assert checked
        assert disagreements == []
    finally:
        idapro.close_database(False)
