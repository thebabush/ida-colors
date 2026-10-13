"""Check parsed strings against the string literals in real databases, and chars against the numbers they stand for.

Skipped unless idapro can load an IDA install and IDA_COLORS_IDBS names a directory of .i64 files.
"""

import os
import re
from pathlib import Path

import pytest

from ida_colors.color_parser import parse_full
from ida_colors.numbers import numbers
from ida_colors.strings import strings

# idapro raises a plain ImportError when it can't find an IDA install.
idapro = pytest.importorskip('idapro', exc_type=ImportError)
import ida_auto  # noqa: E402
import ida_bytes  # noqa: E402
import ida_lines  # noqa: E402
import ida_nalt  # noqa: E402
import idautils  # noqa: E402

IDBS_DIR = os.environ.get('IDA_COLORS_IDBS')
IDBS = sorted(Path(IDBS_DIR).glob('*.i64')) if IDBS_DIR else []

_ESCAPE = re.compile(r'\\(x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|.)', re.DOTALL)
_ENCODINGS = {1: 'utf-8', 2: 'utf-16-le', 4: 'utf-32-le'}
_SIMPLE_ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', 'a': '\a', 'b': '\b', 'f': '\f', 'v': '\v'}


def _unescape(text: str) -> str:
    def replace(m: re.Match[str]) -> str:
        escape = m[1]
        if escape[0] == 'x':
            return chr(int(escape[1:], 16))
        if escape[0].isdigit():
            return chr(int(escape, 8))
        return _SIMPLE_ESCAPES.get(escape, escape)

    return _ESCAPE.sub(replace, text)


@pytest.mark.skipif(not IDBS, reason='set IDA_COLORS_IDBS to a directory of .i64 files')
@pytest.mark.parametrize('idb_copy', IDBS, ids=lambda p: p.stem, indirect=True)
def test_strings_agree_with_string_literals(idb_copy: Path) -> None:
    assert idapro.open_database(str(idb_copy), False) == 0
    try:
        ida_auto.auto_wait()
        checked_strings = checked_chars = 0
        disagreements = []
        for ea in idautils.Heads():
            if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                continue
            line = ida_lines.generate_disasm_line(ea, 0)
            tree = parse_full(line)
            for string in strings(tree):
                if string.char:
                    # A char comment spells out a number of the same line, e.g. `push 20h ; ' '`.
                    checked_chars += 1
                    if ord(string.text) not in {number.value for number in numbers(tree)}:
                        disagreements.append((hex(ea), ida_lines.tag_remove(line), string))
                    continue
                assert string.addr is not None
                # The address can be inside a literal, when the string is the tail of a longer one.
                head = ida_bytes.get_item_head(string.addr)
                if not ida_bytes.is_strlit(ida_bytes.get_flags(head)):
                    disagreements.append((hex(ea), ida_lines.tag_remove(line), string, 'not a string literal'))
                    continue
                # The literal's own bytes, up to the end of the item. get_strlit_contents stops early at some control
                # chars and NULs, and reads past Rust and Go literals, which have no terminator.
                end = head + ida_bytes.get_item_size(head)
                raw = ida_bytes.get_bytes(string.addr, end - string.addr) or b''
                encoding = _ENCODINGS[ida_nalt.get_strtype_bpu(ida_nalt.get_str_type(head))]
                try:
                    literal = raw.decode(encoding).rstrip('\0')
                except UnicodeDecodeError:
                    # Binary data typed as a string. How IDA shows invalid bytes is up to IDA.
                    continue
                text = _unescape(string.text)
                checked_strings += 1
                if not (literal.startswith(text) if string.truncated else literal == text):
                    disagreements.append((hex(ea), ida_lines.tag_remove(line), string, literal))
        assert checked_strings
        assert checked_chars
        assert disagreements == []
    finally:
        idapro.close_database(False)
