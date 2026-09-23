"""Tests for the CLI pretty-printer (skipped when idapro is unavailable, since the CLI imports it)."""

import pytest

from ida_colors.color_parser import parse_full

# idapro raises a plain ImportError when it can't find an IDA install.
pytest.importorskip('idapro', exc_type=ImportError)
cli = pytest.importorskip('ida_colors.__main__')


def test_pp_instruction() -> None:
    raw = '\x01\x05mov\x02\x05     \x01)\x01!rax\x02!\x02)\x01\t,\x02\t \x01*\x01!rbx\x02!\x02*'
    assert list(cli.pp(parse_full(raw))) == ['Insn("mov")', 'Opnd1(Reg("rax"))', 'Opnd2(Reg("rbx"))']


def test_pp_single_colored_node() -> None:
    assert list(cli.pp(parse_full('\x01\x05nop\x02\x05'))) == ['Insn("nop")']


def test_pp_empty_line() -> None:
    assert list(cli.pp(parse_full(''))) == []


def test_check_roundtrip_passes() -> None:
    raw = '\x01\x05mov\x02\x05     \x01)\x01!rax\x02!\x02)\x01\t,\x02\t \x01*\x01!rbx\x02!\x02*'
    cli.check_roundtrip(0x1000, cli.ida_lines.tag_remove(raw), parse_full(raw))


def test_check_roundtrip_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = '\x01\x05nop\x02\x05'
    # Make the parser's side disagree with IDA's.
    monkeypatch.setattr(cli.color_parser, 'tag_remove', lambda _colors: 'nope')
    with pytest.raises(cli.RoundtripError, match=r"00001000: .*'nop'.*'nope'"):
        cli.check_roundtrip(0x1000, cli.ida_lines.tag_remove(raw), parse_full(raw))
