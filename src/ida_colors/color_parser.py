import string
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from enum import Enum

from ida_colors._compat import assert_never

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


@dataclass(slots=True)
class ColorNode:
    color: int | None
    content: Sequence['Colors']


@dataclass(slots=True)
class ColorAddr:
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

_ON = chr(ControlChar.COLOR_ON.value)
_OFF = chr(ControlChar.COLOR_OFF.value)
_ESC = chr(ControlChar.COLOR_ESC.value)
_INV = chr(ControlChar.COLOR_INV.value)
_ADDR = chr(ControlChar.COLOR_ADDR.value)
_SEMSPAN = chr(ColorTag.SEMSPAN.value)
_CONTROL = frozenset((_ON, _OFF, _ESC, _INV))


def _text_end(s: str, i: int) -> int:
    # A char at a time beats a regex here: IDA's text runs are a few chars long, and a match object per run costs more.
    n = len(s)
    while i < n and s[i] not in _CONTROL:
        i += 1
    return i


def parse_colored_string(s: str, address_size: AddressSize = AddressSize.BITS_64) -> ColorNode:
    """Parse colored string."""
    size = address_size.value
    n = len(s)
    # Stack of open tags and their content. The bottom entry is the colorless root.
    stack: list[tuple[int | None, list[Colors]]] = [(None, [])]
    i = 0
    while i < n:
        c = s[i]
        content = stack[-1][1]
        if c == _ON:
            if i + 1 == n:
                raise ParseError('Unexpected end of input')
            tag = s[i + 1]
            if tag == _ADDR:
                # The address is as many hex digits as address_size, then its text up to the next control char.
                addr_hex = s[i + 2 : i + 2 + size]
                if len(addr_hex) < size:
                    raise ParseError('Unexpected end of input')
                # Checked by hand because int(x, 16) also takes signs, whitespace, underscores and a 0x prefix.
                if not _HEX_DIGITS.issuperset(addr_hex):
                    raise ParseError(f'Invalid hex address: {addr_hex}')
                end = _text_end(s, i + 2 + size)
                content.append(ColorAddr(addr=int(addr_hex, 16), text=s[i + 2 + size : end]))
                i = end
            elif tag == _SEMSPAN:
                # The header is dropped like tag_remove does. The span is an ordinary tag 54 node. The header is one
                # kind byte, plus an escaped tid payload as long as an address for SEMK_LOCAL_TYPE_BY_TID (3).
                if i + 2 == n or (s[i + 2] == _ESC and i + 3 + size > n):
                    raise ParseError('Unexpected end of input')
                i += 3 + size if s[i + 2] == _ESC else 3
                stack.append((ColorTag.SEMSPAN.value, []))
            else:
                stack.append((ord(tag), []))
                i += 2
        elif c == _OFF:
            if i + 1 == n:
                raise ParseError('Unexpected end of input')
            # IDA sometimes emits an OFF with no matching ON (e.g. `__unwind {` comments). Skip it like tag_remove does.
            if len(stack) > 1 and stack[-1][0] == ord(s[i + 1]):
                color, children = stack.pop()
                stack[-1][1].append(ColorNode(color=color, content=children))
            i += 2
        elif c == _INV:
            # A lone invisible byte with no tag or payload, e.g. two before a Hex-Rays `}`. Skip it like tag_remove.
            i += 1
        else:
            # Plain text, through escapes: an ESC takes the next char as text, whatever it is, or nothing at the end.
            end = _text_end(s, i)
            text = s[i:end]
            while end < n and s[end] == _ESC:
                i, end = end, _text_end(s, min(end + 2, n))
                text += s[i + 1 : end]
            i = end
            # Text on both sides of a skipped OFF or INV joins into one string.
            if content and isinstance(content[-1], str):
                content[-1] += text
            elif text:
                content.append(text)
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
            assert_never(node)


def iter_nodes(node: Colors) -> Iterator[ColorNode]:
    """Yield every colored node, the tree itself included, top-down in the order they're printed."""
    # A stack instead of recursion, which would resume a generator per level for every node.
    stack = [node] if isinstance(node, ColorNode) else []
    while stack:
        current = stack.pop()
        yield current
        stack.extend([child for child in reversed(current.content) if isinstance(child, ColorNode)])
