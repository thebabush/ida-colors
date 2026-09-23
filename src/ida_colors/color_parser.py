import re
import string
from collections.abc import Sequence
from enum import Enum
from functools import cache

from pydantic import BaseModel

# --------------------
# Enums
# --------------------


class ControlChar(Enum):
    """IDA Pro control characters for colored strings."""

    COLOR_ON = 0x01
    COLOR_OFF = 0x02
    COLOR_ESC = 0x03
    COLOR_INV = 0x04
    COLOR_ADDR = 0x28


class AddressSize(Enum):
    """Address size for parsing colored strings."""

    BITS_32 = 8
    BITS_64 = 16


class ColorNode(BaseModel):
    color: int | None
    content: Sequence['Colors']


class ColorAddr(BaseModel):
    addr: int
    text: str


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
    REGCMT = 2
    RPTCMT = 3
    AUTOCMT = 4
    INSN = 5
    DATNAME = 6
    DNAME = 7
    DEMNAME = 8
    SYMBOL = 9
    CHAR = 10
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
    ADDR = 40  # Also FG_MAX
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
    ADDR_EXPR = 53
    GROUP = 54
    SEMSPAN = 54  # noqa: PIE796  # Intentional alias: IDA's name for GROUP after 9.4, which added a header.

    @classmethod
    def from_int(cls, value: int) -> 'ColorTag':
        try:
            return cls(value)
        except ValueError:
            raise UnknownColorError(value) from None


# --------------------
# Parser
# --------------------


class ParseError(Exception):
    """Error during parsing."""


_HEX_DIGITS = frozenset(string.hexdigits)


@cache
def _tokenizer(address_size: AddressSize) -> re.Pattern[str]:
    # One token per match. Address text stops at any control char. Plain text runs through escapes (ESC + any char).
    # A SEMSPAN header is one kind byte, plus a tid payload as long as an address for SEMK_LOCAL_TYPE_BY_TID (3).
    return re.compile(
        rf'(?P<addr>\x01\x28)(?:(?P<hex>.{{{address_size.value}}})(?P<addr_text>[^\x01-\x04]*))?'
        rf'|(?P<semspan>\x01\x36)(?P<sem_header>\x03.{{{address_size.value}}}|[^\x03])?'
        r'|\x01(?P<on>.)'
        r'|\x02(?P<off>.)'
        r'|(?P<text>(?:[^\x01-\x04]|\x03.?)+)'
        r'|(?P<bad>.)',
        re.DOTALL,
    )


def parse_colored_string(s: str, address_size: AddressSize = AddressSize.BITS_64) -> ColorNode:
    """Parse colored string."""
    # Stack of open tags and their content. The bottom entry is the colorless root.
    stack: list[tuple[int | None, list[Colors]]] = [(None, [])]
    for m in _tokenizer(address_size).finditer(s):
        content = stack[-1][1]
        if m['addr'] is not None:
            if (addr_hex := m['hex']) is None:
                raise ParseError('Unexpected end of input')
            # Checked by hand because int(x, 16) also takes signs, whitespace, underscores and a 0x prefix.
            if not _HEX_DIGITS.issuperset(addr_hex):
                raise ParseError(f'Invalid hex address: {addr_hex}')
            content.append(ColorAddr(addr=int(addr_hex, 16), text=m['addr_text']))
        elif m['semspan'] is not None:
            # The header is dropped like tag_remove does. The span is an ordinary tag 54 node.
            if m['sem_header'] is None:
                raise ParseError('Unexpected end of input')
            stack.append((ColorTag.SEMSPAN.value, []))
        elif (on := m['on']) is not None:
            stack.append((ord(on), []))
        elif (off := m['off']) is not None:
            # IDA sometimes emits an OFF with no matching ON (e.g. `__unwind {` comments). Skip it like tag_remove does.
            if len(stack) > 1 and stack[-1][0] == ord(off):
                color, children = stack.pop()
                stack[-1][1].append(ColorNode(color=color, content=children))
        elif (text := m['text']) is not None:
            text = re.sub(r'\x03(.?)', r'\1', text, flags=re.DOTALL)
            # Text on both sides of a skipped OFF or INV joins into one string.
            if content and isinstance(content[-1], str):
                content[-1] += text
            elif text:
                content.append(text)
        elif m['bad'] == chr(ControlChar.COLOR_INV.value):
            # A lone invisible byte with no tag or payload, e.g. two before a Hex-Rays `}`. Skip it like tag_remove.
            continue
        else:
            raise ParseError('Unexpected end of input')
    if len(stack) > 1:
        raise ParseError('Unclosed color tag')
    return ColorNode(color=None, content=stack[0][1])


def simplify_color_tree(node: Colors) -> Colors:
    """Unwrap the colorless root when its only child is a colored node."""
    # Only the root is colorless in a parsed tree, so there is nothing to simplify below it.
    match node:
        case ColorNode(color=None, content=[ColorNode() as child]):
            return child
        case _:
            return node


def parse_full(s: str, address_size: AddressSize = AddressSize.BITS_64) -> Colors:
    """Parse a colored string and simplify it."""
    return simplify_color_tree(parse_colored_string(s, address_size))


def tag_remove(node: Colors) -> str:
    """Remove all color tags from a colored string."""
    match node:
        case ColorNode(content=content):
            return ''.join([tag_remove(c) for c in content])
        case ColorAddr(text=text):
            return text
        case str():
            return node
        case _:
            raise ValueError(f'Unknown node: {node}')
