"""Tests for the CLI pretty-printer (skipped when idapro is unavailable, since the CLI imports it)."""

import pytest

from ida_colors.color_parser import parse_full

# idapro raises a plain ImportError when it can't find an IDA install.
pytest.importorskip('idapro', exc_type=ImportError)
cli = pytest.importorskip('ida_colors.__main__')


def test_pp_instruction() -> None:
    raw = '\x01\x05mov\x02\x05     \x01)\x01!rax\x02!\x02)\x01\t,\x02\t \x01*\x01!rbx\x02!\x02*'
    assert list(cli.pp(parse_full(raw))) == ['Insn("mov")', 'Opnd1(Reg("rax"))', 'Opnd2(Reg("rbx"))']


# Known bug: a line that is one colored node simplifies to that node, and pp() then prints its child only.
@pytest.mark.xfail(strict=True, reason='pp() unpacks the node it gets instead of printing it')
def test_pp_single_colored_node() -> None:
    assert list(cli.pp(parse_full('\x01\x05nop\x02\x05'))) == ['Insn("nop")']


# Known bug: pp() unpacks the first child as the mnemonic, which fails on an empty line.
@pytest.mark.xfail(strict=True, raises=ValueError, reason='pp() assumes at least one child')
def test_pp_empty_line() -> None:
    assert list(cli.pp(parse_full(''))) == []
