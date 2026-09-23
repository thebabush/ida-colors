import pytest

from ida_colors.color_parser import (
    ColorAddr,
    ColorNode,
    ColorTag,
    ParseError,
    UnknownColorError,
    parse_colored_string,
    parse_full,
    tag_remove,
)


def test_parse_keeps_colorless_root() -> None:
    raw = '\x01)\x01!rsp\x02!\x02)'
    assert parse_colored_string(raw) == ColorNode(
        color=None,
        content=[ColorNode(color=41, content=[ColorNode(color=33, content=['rsp'])])],
    )


def test_parse_full_unwraps_root() -> None:
    raw = '\x01)\x01!rsp\x02!\x02)'
    assert parse_full(raw) == ColorNode(color=41, content=[ColorNode(color=33, content=['rsp'])])


def test_parse_full_keeps_root_with_several_children() -> None:
    raw = '\x01\x05nop\x02\x05 x'
    assert parse_full(raw) == ColorNode(color=None, content=[ColorNode(color=5, content=['nop']), ' x'])


def test_addr() -> None:
    raw = '\x01)\x01!cs\x02!\x01\t:\x02\t\x01\x06\x01(00000000008604D8off_8604D8\x02\x06\x02)'
    assert parse_full(raw) == ColorNode(
        color=41,
        content=[
            ColorNode(color=33, content=['cs']),
            ColorNode(color=9, content=[':']),
            ColorNode(color=6, content=[ColorAddr(addr=0x8604D8, text='off_8604D8')]),
        ],
    )


def test_byte_ptr() -> None:
    raw = '\x01)\x01 byte ptr\x02  \x01\t[\x02\t\x01!rbp\x02!\x01\t+\x02\t\x01\x0c1\x02\x0c\x01\t]\x02\t\x02)'
    assert parse_full(raw) == ColorNode(
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
    assert tag_remove(parse_full(raw)) == 'byte ptr [rbp+1]'


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
        ('\x01\x05\x01\x06a\x02\x05\x02\x06', ParseError),  # crossed tags: OFF 5 is skipped, so 5 stays open
    ],
)
def test_errors(raw: str, error: type[Exception]) -> None:
    with pytest.raises(error):
        parse_colored_string(raw)


# Known bug: int(x, 16) accepts more than hex digits, so these parse instead of raising ParseError.
@pytest.mark.xfail(strict=True, reason='address is parsed with int(x, 16), which accepts non-hex syntax')
@pytest.mark.parametrize(
    'raw',
    [
        '\x01(0000_00000001234',  # underscore
        '\x01( 000000000001234',  # whitespace
        '\x01(-000000000001234',  # sign, even parses as a negative address
        '\x01(0x00000000001234',  # 0x prefix
    ],
)
def test_non_hex_address_is_rejected(raw: str) -> None:
    with pytest.raises(ParseError):
        parse_colored_string(raw)


def test_unknown_color_tag() -> None:
    assert ColorTag.from_int(33) is ColorTag.REG
    with pytest.raises(UnknownColorError, match='0x31'):
        ColorTag.from_int(0x31)
