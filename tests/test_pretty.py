from ida_colors.color_parser import ColorAddr, ColorNode, ColorTag, parse_colored_string, parse_full
from ida_colors.pretty import format_line, format_node, to_json


def test_format_line_instruction() -> None:
    raw = '\x01\x05mov\x02\x05     \x01)\x01!rax\x02!\x02)\x01\t,\x02\t \x01*\x01!rbx\x02!\x02*'
    assert format_line(parse_full(raw)) == ['Insn("mov")', 'Opnd1(Reg("rax"))', 'Opnd2(Reg("rbx"))']


def test_format_line_single_colored_node() -> None:
    assert format_line(parse_full('\x01\x05nop\x02\x05')) == ['Insn("nop")']


def test_format_line_empty_line() -> None:
    assert format_line(parse_full('')) == []


def test_format_line_skips_comma_symbol() -> None:
    comma = ColorNode(color=ColorTag.SYMBOL.value, content=[','])
    other_symbol = ColorNode(color=ColorTag.SYMBOL.value, content=['+'])
    line = ColorNode(color=None, content=['push', comma, ' ', other_symbol])
    assert format_line(line) == ['"push"', 'Symbol("+")']


def test_format_node_nested() -> None:
    node = ColorNode(color=ColorTag.OPND1.value, content=[ColorNode(color=ColorTag.REG.value, content=['rax']), 'x'])
    assert format_node(node) == 'Opnd1(Reg("rax"), "x")'


def test_format_node_colorless() -> None:
    assert format_node(ColorNode(color=None, content=['a'])) == '_("a")'


def test_format_node_addr() -> None:
    assert format_node(ColorAddr(addr=0x1234, text='name')) == "Addr(00001234, 'name')"


def test_format_node_string_is_json_quoted() -> None:
    assert format_node('say "hi"') == r'"say \"hi\""'


def test_format_node_skips_whitespace_children() -> None:
    node = ColorNode(color=ColorTag.INSN.value, content=['  ', 'mov', '\t'])
    assert format_node(node) == 'Insn("mov")'


def test_to_json_string() -> None:
    assert to_json('mov') == 'mov'


def test_to_json_nested() -> None:
    node = ColorNode(color=ColorTag.OPND1.value, content=[ColorNode(color=ColorTag.REG.value, content=['rax']), 'x'])
    assert to_json(node) == {'tag': 'OPND1', 'children': [{'tag': 'REG', 'children': ['rax']}, 'x']}


def test_to_json_addr_decimal() -> None:
    assert to_json(ColorAddr(addr=0x1234, text='name')) == {'addr': '4660', 'text': 'name'}


def test_to_json_addr_hex() -> None:
    assert to_json(ColorAddr(addr=0x1234, text='name'), hex_addrs=True) == {'addr': '0x1234', 'text': 'name'}


def test_to_json_unknown_tag_is_int() -> None:
    assert to_json(ColorNode(color=0x31, content=['a'])) == {'tag': 0x31, 'children': ['a']}


def test_to_json_colorless() -> None:
    assert to_json(ColorNode(color=None, content=['a'])) == {'tag': None, 'children': ['a']}


def test_to_json_full_line() -> None:
    raw = '\x01\x05mov\x02\x05     \x01)\x01!rax\x02!\x02)\x01\t,\x02\t \x01*\x01!rbx\x02!\x02*'
    assert [to_json(c) for c in parse_colored_string(raw).content] == [
        {'tag': 'INSN', 'children': ['mov']},
        '     ',
        {'tag': 'OPND1', 'children': [{'tag': 'REG', 'children': ['rax']}]},
        {'tag': 'SYMBOL', 'children': [',']},
        ' ',
        {'tag': 'OPND2', 'children': [{'tag': 'REG', 'children': ['rbx']}]},
    ]
