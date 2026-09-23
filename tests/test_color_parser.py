import json
from typing import Any

import pytest
from pydantic import BaseModel

from ida_colors.color_parser import (
    ColorAddr,
    ColorNode,
    Colors,
    ColorTag,
    ParseError,
    parse_colored_string,
    parse_full,
    simplify_color_tree,
    tag_remove,
)


def parse_lift(s: str) -> Colors:
    tree = parse_colored_string(s)
    print(tree)
    return tree


def dump_with_types(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        cls = obj.__class__
        result = {'_': cls.__name__}
        for field in obj.__class__.model_fields:
            if field == 'color' and getattr(obj, 'color', None) is not None:
                color_val = obj.color
                result[field] = ColorTag.from_int(color_val).name
            else:
                result[field] = dump_with_types(getattr(obj, field))
        return result

    elif isinstance(obj, list):
        return [dump_with_types(item) for item in obj]

    elif isinstance(obj, dict):
        return {k: dump_with_types(v) for k, v in obj.items()}

    else:
        return obj  # base types (str, int, etc.)


def test_parse_colored_string_easy() -> None:
    raw = '\x01)\x01!rsp\x02!\x02)'
    parse_lift(raw)


def test_parse_colored_string_addr() -> None:
    raw = '\x01)\x01!cs\x02!\x01\t:\x02\t\x01\x06\x01(00000000008604D8off_8604D8\x02\x06\x02)'
    tree = parse_lift(raw)
    tree = simplify_color_tree(tree)
    print(json.dumps(dump_with_types(tree), indent=2))
    target = ColorNode(
        color=41,
        content=[
            ColorNode(color=33, content=['cs']),
            ColorNode(color=9, content=[':']),
            ColorNode(color=6, content=[ColorAddr(addr=8783064, text='off_8604D8')]),
        ],
    )
    assert tree == target


def test_parse_colored_byte_ptr() -> None:
    raw = '\x01)\x01 byte ptr\x02  \x01\t[\x02\t\x01!rbp\x02!\x01\t+\x02\t\x01\x0c1\x02\x0c\x01\t]\x02\t\x02)'
    colors = parse_lift(raw)
    colors = simplify_color_tree(colors)
    target = ColorNode(
        color=41,
        content=[
            ColorNode(color=32, content=['byte ptr']),
            ' ',
            ColorNode(color=9, content=['[']),
            ColorNode(color=33, content=['rbp']),
            ColorNode(color=9, content=['+']),
            ColorNode(color=12, content=['1']),
            ColorNode(color=9, content=[']']),
        ],
    )
    assert colors == target


def test_stray_color_off_is_skipped() -> None:
    # From a C++ listing: IDA closes the REGCMT (0x02) comment one time too many.
    raw = (
        '\x01\x13.text:000000000001EE40\x02\x13 \x01\x02;\x02\x02 \x01 __unwind\x02  \x01\t{\x02\t '
        '\x01\x02// \x01"\x01(0000000000083700__gxx_personality_v0\x02"\x02\x02\x02\x02'
    )
    tree = parse_full(raw)
    assert tag_remove(tree) == '.text:000000000001EE40 ; __unwind { // __gxx_personality_v0'
    assert isinstance(tree, ColorNode)
    assert tree.content[-1] == ColorNode(
        color=2,
        content=['// ', ColorNode(color=34, content=[ColorAddr(addr=0x83700, text='__gxx_personality_v0')])],
    )


def test_stray_color_off_joins_text() -> None:
    assert parse_colored_string('a\x02\x05b') == ColorNode(color=None, content=['ab'])


def test_escapes() -> None:
    # ESC quotes the next char, even a control char. A trailing ESC is dropped.
    assert parse_colored_string('a\x03\x01b\x03') == ColorNode(color=None, content=['a\x01b'])


def test_addr_text_stops_at_escape() -> None:
    raw = '\x01(0000000000001234ab\x03!c'
    assert parse_colored_string(raw) == ColorNode(color=None, content=[ColorAddr(addr=0x1234, text='ab'), '!c'])


@pytest.mark.parametrize(
    ('raw', 'error'),
    [
        ('\x01\x05abc', ParseError),  # unclosed tag
        ('\x01', ParseError),  # ON without a tag
        ('\x01(0123', ParseError),  # truncated address
        ('\x01(zzzzzzzzzzzzzzzz', ParseError),  # non-hex address
        ('a\x04b', NotImplementedError),  # COLOR_INV
    ],
)
def test_errors(raw: str, error: type[Exception]) -> None:
    with pytest.raises(error):
        parse_colored_string(raw)
