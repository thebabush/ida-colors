from enum import Enum
from typing import Any, NewType, Optional, Sequence

import lark
from lark import Lark, Transformer
from lark.exceptions import LarkError
from pydantic import BaseModel

# --------------------
# Address Size Enum
# --------------------


class AddressSize(Enum):
    """Address size for parsing colored strings."""

    BITS_32 = 8
    BITS_64 = 16  # Default


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


class UnknownColorError(ValueError):
    def __init__(self, value: int):
        super().__init__(f'Unknown COLOR tag: 0x{value:02X}')
        self.value = value


class ColorTag(Enum):
    """IDA Pro color tag constants."""

    DEFAULT = 1
    SELECTED = 2
    RPTCMT = 3
    REGFUNC = 4
    INSN = 5
    DATNAME = 6
    UNKNOWN = 7
    EXTERN = 8
    SYMBOL = 9
    CURLINE = 10
    STRING = 11
    NUMBER = 12
    VOIDOP = 13
    CREF = 14
    DREF = 15
    CREFTAIL = 16
    DREFTAIL = 17
    ERROR = 18
    PREFIX = 19
    BINPREF = 20
    EXTRA = 21
    ALTOP = 22
    HIDNAME = 23
    LIBNAME = 24
    LOCNAME = 25
    CODNAME = 26
    ASMDIR = 27
    MACRO = 28
    DSTR = 29
    DCHAR = 30
    DNUM = 31
    KEYWORD = 32
    REG = 33
    IMPNAME = 34
    SEGNAME = 35
    UNKNAME = 36
    CNAME = 37
    UNAME = 38
    COLLAPSED = 39
    FG_MAX = 40
    OPND1 = 41
    OPND2 = 42
    OPND3 = 43
    OPND4 = 44
    OPND5 = 45
    OPND6 = 46
    OPND7 = 47
    OPND8 = 48
    RESERVED1 = 51
    LUMINA = 52

    @classmethod
    def from_int(cls, value: int) -> 'ColorTag':
        try:
            return cls(value)
        except ValueError:
            raise UnknownColorError(value)


# --------------------
# Lark Grammar and Parser
# --------------------


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


class ColorParser:
    """Parser for IDA Pro colored strings with configurable address size."""

    def __init__(self, address_size: AddressSize = AddressSize.BITS_64):
        self.address_size = address_size
        self._grammar = self._build_grammar()
        self._parser = Lark(self._grammar, parser='lalr')
        self._transformer = ColorTransformer()

    def _build_grammar(self) -> str:
        """Build Lark grammar based on address size."""
        addr_hex_chars = self.address_size.value
        return f"""
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

COLOR_ON: "\\x01"
COLOR_OFF: "\\x02"
COLOR_ESC: "\\x03"
COLOR_INV: "\\x04"
COLOR_ADDR: "\\x28"
color_tag: /./
addr_bytes: /[0-9a-fA-F]{{{addr_hex_chars}}}/
CHAR: /[^\\x01-\\x04]/
ANY_CHAR: /./
"""

    def parse(self, s: str) -> lark.Tree:
        """Parse colored string using Lark parser."""
        try:
            return self._parser.parse(s)
        except LarkError:
            raise

    def lift_ast(self, ast: lark.Tree) -> ColorNode:
        """Lift AST to ColorNode."""
        return self._transformer.transform(ast)

    def parse_full(self, s: str) -> Colors:
        """Parse a colored string and simplify it."""
        tree = self.parse(s)
        colors = self.lift_ast(tree)
        colors = simplify_color_tree(colors)
        return colors


# --------------------
# Main Parser
# --------------------


def parse_colored_string(s: str, address_size: AddressSize = AddressSize.BITS_64) -> lark.Tree:
    """Parse colored string using Lark parser."""
    parser = ColorParser(address_size)
    return parser.parse(s)


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


def parse_full(s: str, address_size: AddressSize = AddressSize.BITS_64) -> Colors:
    """Parse a colored string and simplify it."""
    parser = ColorParser(address_size)
    return parser.parse_full(s)


def pp(node: Colors, indent: int = 0, level: int = 0) -> str:
    """Pretty print a colored string."""
    match node:
        case ColorNode(color=color, content=content):
            if color is not None:
                color_name = ColorTag.from_int(color).name
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
