"""Parse and pretty-print IDA Pro color-tagged strings, without needing IDA itself."""

from ida_colors.color_parser import (
    AddressSize,
    ColorAddr,
    ColorNode,
    Colors,
    ColorTag,
    ControlChar,
    ParseError,
    UnknownColorError,
    iter_nodes,
    parse_colored_string,
    parse_full,
    simplify_color_tree,
    tag_remove,
)
from ida_colors.numbers import Number, numbers, parse_int
from ida_colors.pretty import format_line, format_node
from ida_colors.strings import String, strings

__all__ = [
    'AddressSize',
    'ColorAddr',
    'ColorNode',
    'ColorTag',
    'Colors',
    'ControlChar',
    'Number',
    'ParseError',
    'String',
    'UnknownColorError',
    'format_line',
    'format_node',
    'iter_nodes',
    'numbers',
    'parse_colored_string',
    'parse_full',
    'parse_int',
    'simplify_color_tree',
    'strings',
    'tag_remove',
]
