"""Check the constants copied from IDA against a real IDA install (skipped when idapro is unavailable)."""

import ast
from pathlib import Path

import pytest

# Import before idapro: initializing IDA rewrites sys.path, dropping the repo root.
from ida_colors.color_parser import AddressSize, ColorTag, ControlChar

# idapro raises a plain ImportError when it can't find an IDA install.
pytest.importorskip('idapro', exc_type=ImportError)
ida_lines = pytest.importorskip('ida_lines')


def _ida_color_tags() -> dict[str, int]:
    """Collect IDA's color tags (color_t), leaving out its background colors (bgcolor_t).

    Both are COLOR_* ints in ida_lines, and some share values. SWIG exposes the tags as
    `COLOR_X = cvar.COLOR_X` and the background colors as `COLOR_X = _ida_lines.COLOR_X`.
    """
    tree = ast.parse(Path(ida_lines.__file__).read_text())
    return {
        target.id: getattr(ida_lines, target.id)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == 'cvar'
        for target in node.targets
        if isinstance(target, ast.Name) and target.id.startswith('COLOR_')
    }


IDA_COLOR_TAGS = _ida_color_tags()


@pytest.mark.parametrize('tag', list(ColorTag), ids=lambda t: t.name)
def test_color_tag(tag: ColorTag) -> None:
    assert IDA_COLOR_TAGS.get(f'COLOR_{tag.name}') == tag.value


def test_color_tag_coverage() -> None:
    # IDA has aliases (e.g. COLOR_CMT == COLOR_NUMBER), so only values need to be covered.
    ours = {tag.value for tag in ColorTag}
    missing = {name: value for name, value in IDA_COLOR_TAGS.items() if value not in ours}
    assert not missing


@pytest.mark.parametrize('char', list(ControlChar), ids=lambda c: c.name)
def test_control_char(char: ControlChar) -> None:
    expected = getattr(ida_lines, char.name)
    # COLOR_ON & co. are one-char strings in IDA, COLOR_ADDR is an int.
    if isinstance(expected, str):
        expected = ord(expected)
    assert char.value == expected


def test_control_char_coverage() -> None:
    ida_chars = {
        name for name in dir(ida_lines) if name.startswith('COLOR_') and isinstance(getattr(ida_lines, name), str)
    }
    assert ida_chars <= {char.name for char in ControlChar}


def test_address_size() -> None:
    # IDA 9 is 64-bit only, so BITS_32 can't be checked.
    assert AddressSize.BITS_64.value == ida_lines.COLOR_ADDR_SIZE
