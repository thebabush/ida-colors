"""Check the constants copied from IDA against a real IDA install (skipped when idapro is unavailable)."""

import pytest

# Import before idapro: initializing IDA rewrites sys.path, dropping the repo root.
from ida_colors.color_parser import AddressSize, ColorTag, ControlChar

# idapro raises a plain ImportError when it can't find an IDA install.
pytest.importorskip('idapro', exc_type=ImportError)
ida_lines = pytest.importorskip('ida_lines')


@pytest.mark.parametrize('tag', list(ColorTag), ids=lambda t: t.name)
def test_color_tag(tag: ColorTag) -> None:
    assert tag.value == getattr(ida_lines, f'COLOR_{tag.name}')


@pytest.mark.parametrize('char', list(ControlChar), ids=lambda c: c.name)
def test_control_char(char: ControlChar) -> None:
    expected = getattr(ida_lines, char.name)
    # COLOR_ON & co. are one-char strings in IDA, COLOR_ADDR is an int.
    if isinstance(expected, str):
        expected = ord(expected)
    assert char.value == expected


def test_address_size() -> None:
    # IDA 9 is 64-bit only, so BITS_32 can't be checked.
    assert AddressSize.BITS_64.value == ida_lines.COLOR_ADDR_SIZE
