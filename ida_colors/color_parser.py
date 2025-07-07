from typing import Any, NewType, Optional, Sequence

import lark
from lark import Lark, Transformer
from lark.exceptions import LarkError
from pydantic import BaseModel

import idapro as _  # noqa: F401 # isort: skip
import ida_lines

# --------------------
# Pydantic Models
# --------------------


Color = NewType('Color', int)


class ColorAstBaseModel(BaseModel):
    pass


class ColorToken(ColorAstBaseModel):
    color: Optional[str]
    text: str


class ColorNode(ColorAstBaseModel):
    color: int | None
    content: Sequence['Colors']


class ColorAddr(ColorAstBaseModel):
    addr: int
    text: str


class ColorOnOff(ColorAstBaseModel):
    color: Color


class ColorOn(ColorOnOff):
    """Intermediate class for color_on_tag."""

    pass


class ColorOff(ColorOnOff):
    """Intermediate class for color_off_tag."""

    pass


Colors = ColorNode | str | ColorAddr


# --------------------
# IDA Color Definitions
# --------------------


def normalize_char(c: str | int) -> int:
    if isinstance(c, str):
        return ord(c)
    assert c >= 0 and c <= 255
    return c


COLOR_ON = normalize_char(ida_lines.COLOR_ON)
COLOR_OFF = normalize_char(ida_lines.COLOR_OFF)
COLOR_ESC = normalize_char(ida_lines.COLOR_ESC)
COLOR_INV = normalize_char(ida_lines.COLOR_INV)
COLOR_ADDR = normalize_char(ida_lines.COLOR_ADDR)

# COLOR_ADDR_SIZE constant (typically 8 bytes for 32-bit addresses)
COLOR_ADDR_SIZE = ida_lines.COLOR_ADDR_SIZE


class UnknownColorError(ValueError):
    def __init__(self, value: int):
        super().__init__(f'Unknown COLOR tag: 0x{value:02X}')
        self.value = value


def get_color_tags() -> dict[int, str]:
    """Dynamically extract COLOR_ constants from ida_lines."""
    return {
        value: name
        for name, value in vars(ida_lines).items()
        if name.startswith('COLOR_') and isinstance(value, int)
    }


COLOR_TAGS = get_color_tags()


def get_color_name(color_val: int) -> str:
    """Convert color byte to symbolic name. Raises if unknown."""
    if color_val not in COLOR_TAGS:
        raise UnknownColorError(color_val)
    return COLOR_TAGS[color_val]


# --------------------
# Lark Grammar
# --------------------

GRAMMAR = f"""
?start: content*

content: color_addr
       | color_node
       | color_inv
       | texts

color_node: color_on_tag content* color_off_tag
color_addr: COLOR_ON COLOR_ADDR addr_bytes texts
color_inv: COLOR_INV
texts: text+

text: escaped_char | CHAR

color_on_tag: COLOR_ON color_tag
color_off_tag: COLOR_OFF color_tag
escaped_char: COLOR_ESC ANY_CHAR

COLOR_ON: "\\x{COLOR_ON:02X}"
COLOR_OFF: "\\x{COLOR_OFF:02X}"
COLOR_ESC: "\\x{COLOR_ESC:02X}"
COLOR_INV: "\\x{COLOR_INV:02X}"
COLOR_ADDR: "\\x{COLOR_ADDR:02X}" # '('
color_tag: /./
addr_bytes: /[0-9a-fA-F]{{{COLOR_ADDR_SIZE}}}/
CHAR: /[^\x01-\x04]/
ANY_CHAR: /./
"""


class ColorTransformer(Transformer):
    def __init__(self) -> None:
        super().__init__()

    def text(self, chars: list[str]) -> str:
        return ''.join(chars)

    def escaped_char(self, items: list) -> str:
        return items[1]

    def color_inv(self, items: Any) -> None:
        raise NotImplementedError('COLOR_INV is not supported')
        # This escape character has no corresponding #COLOR_OFF.
        # Its action continues until the next #COLOR_INV or end of line.

    def color_addr(self, items: list) -> ColorAddr:
        _1, _2, addr, text = items
        return ColorAddr(addr=addr, text=text)

    def texts(self, items: list[str]) -> str:
        return ''.join(items)

    def color_off_tag(self, items: list[lark.Token]) -> ColorOff:
        return ColorOff(color=Color(ord(items[1].value)))

    def color_on_tag(self, items: list[lark.Token]) -> ColorOn:
        return ColorOn(color=Color(ord(items[1].value)))

    def color_node(self, items: list) -> ColorNode:
        color_on: ColorOn = items[0]
        color_off: ColorOff = items[-1]

        # Validate matching tags
        if color_on.color != color_off.color:
            raise ValueError(f'Mismatched color tags: {color_on} vs {color_off}')

        content = items[1:-1]  # Everything between color tags

        return ColorNode(color=color_on.color, content=content)

    def color_tag(self, items: list[str]) -> str:
        return items[0]

    def addr_bytes(self, items: list[lark.Token]) -> int:
        assert len(items) == 1
        return int(items[0].value, 16)

    def start(self, items: Sequence[ColorNode]) -> ColorNode:
        return ColorNode(color=None, content=items)

    def content(self, items: list) -> ColorNode:
        return ColorNode(color=None, content=items)


# --------------------
# Main Parser
# --------------------


def parse_colored_string(s: str) -> lark.Tree:
    """Parse colored string using Lark parser."""
    try:
        parser = Lark(GRAMMAR, parser='lalr')  # , transformer=ColorTransformer())
        tree = parser.parse(s)
        return tree
    except LarkError:
        raise


def lift_ast(ast: lark.Tree) -> ColorNode:
    """Lift AST to ColorNode."""
    transformer = ColorTransformer()
    return transformer.transform(ast)


def simplify_one(node: Colors) -> Colors:
    """Simplify a single node."""
    match node:
        case ColorNode(color=None, content=[ColorNode()]):
            return node.content[0]
        case ColorNode(color=color, content=[ColorNode(color=None, content=content)]):
            return ColorNode(color=color, content=content)
        case _:
            return node


def simplify_color_tree(node: Colors) -> Colors:
    match node:
        case ColorNode():
            content = list(node.content)
            for ith, child in enumerate(content):
                content[ith] = simplify_color_tree(child)
            node.content = content
            node = simplify_one(node)
        case _:
            pass

    return node


def parse_full(s: str) -> Colors:
    """Parse a colored string and simplify it."""
    tree = parse_colored_string(s)
    colors = lift_ast(tree)
    colors = simplify_color_tree(colors)
    return colors


def pp(node: Colors, indent: int = 0, level: int = 0) -> str:
    """Pretty print a colored string."""
    match node:
        case ColorNode(color=color, content=content):
            if color is not None:
                color_name = get_color_name(color)
            else:
                color_name = '_'

            return f'{"  " * indent}{color_name}\n' + '\n'.join(
                [pp(c, indent + 1, level + 1) for c in content]
            )
        case ColorAddr(addr=addr, text=text):
            return f'{"  " * indent}{addr:08X}: {text}'
        case str():
            return f'{"  " * indent}{node}'
        case None:
            return 'None'
        case _:
            raise ValueError(f'Unknown node: {node}')


def tag_remove(node: Colors) -> str:
    """Remove all color tags from a colored string."""
    match node:
        case ColorNode(color=_, content=content):
            return ''.join([tag_remove(c) for c in content])
        case ColorAddr(addr=_, text=text):
            return text
        case str():
            return node
        case _:
            raise ValueError(f'Unknown node: {node}')
