# Frozen copy of ida_colors at commit cadd518, used as the oracle for behavior-preserving changes. Do not edit.
"""The parts of ida_colors that tests/test_oracle.py checks the live package against."""

from ida_colors_ref.color_parser import (
    AddressSize,
    ColorAddr,
    ColorNode,
    Colors,
    ParseError,
    iter_nodes,
    parse_colored_string,
    parse_full,
    simplify_color_tree,
    tag_remove,
)
from ida_colors_ref.numbers import Number, numbers
from ida_colors_ref.strings import String, strings

__all__ = [
    'AddressSize',
    'ColorAddr',
    'ColorNode',
    'Colors',
    'Number',
    'ParseError',
    'String',
    'iter_nodes',
    'numbers',
    'parse_colored_string',
    'parse_full',
    'simplify_color_tree',
    'strings',
    'tag_remove',
]
