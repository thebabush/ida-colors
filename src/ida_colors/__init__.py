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
    parse_colored_string,
    parse_full,
    simplify_color_tree,
    tag_remove,
)
from ida_colors.pretty import JsonNode, format_addr, format_line, format_node, to_json

__all__ = [
    'AddressSize',
    'ColorAddr',
    'ColorNode',
    'ColorTag',
    'Colors',
    'ControlChar',
    'JsonNode',
    'ParseError',
    'UnknownColorError',
    'format_addr',
    'format_line',
    'format_node',
    'parse_colored_string',
    'parse_full',
    'simplify_color_tree',
    'tag_remove',
    'to_json',
]
