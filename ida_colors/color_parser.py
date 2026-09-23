from collections.abc import Sequence
from enum import Enum
from typing import NewType

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


# --------------------
# Pydantic Models
# --------------------


Color = NewType('Color', int)


class ColorAstBaseModel(BaseModel):
    pass


class ColorToken(ColorAstBaseModel):
    color: str | None
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


class ColorOff(ColorOnOff):
    """Intermediate class for color_off_tag."""


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

    @classmethod
    def from_int(cls, value: int) -> 'ColorTag':
        try:
            return cls(value)
        except ValueError:
            raise UnknownColorError(value) from None


# --------------------
# Custom Parser
# --------------------


class ParseError(Exception):
    """Error during parsing."""


class ColorStringParser:
    """Custom parser for IDA Pro colored strings."""

    def __init__(self, s: str, address_size: AddressSize):
        self.s = s
        self.pos = 0
        self.length = len(s)
        self.address_size = address_size

    def peek(self, offset: int = 0) -> int | None:
        """Peek at byte at current position + offset."""
        idx = self.pos + offset
        if idx < self.length:
            return ord(self.s[idx])
        return None

    def consume(self) -> int:
        """Consume and return current byte."""
        if self.pos >= self.length:
            raise ParseError('Unexpected end of input')
        byte = ord(self.s[self.pos])
        self.pos += 1
        return byte

    def consume_bytes(self, n: int) -> str:
        """Consume n bytes and return as string."""
        if self.pos + n > self.length:
            raise ParseError('Unexpected end of input')
        result = self.s[self.pos : self.pos + n]
        self.pos += n
        return result

    def at_end(self) -> bool:
        """Check if at end of input."""
        return self.pos >= self.length

    def parse_colored_string(self) -> ColorNode:
        """Parse the entire colored string."""
        content = []
        while not self.at_end():
            item = self.parse_content()
            if item is not None:
                content.append(item)
        return ColorNode(color=None, content=content)

    def parse_content(self) -> Colors | None:
        """Parse a content item (color_node, color_addr, or text)."""
        byte = self.peek()
        if byte is None:
            return None

        if byte == ControlChar.COLOR_ON.value:
            next_byte = self.peek(1)
            if next_byte == ControlChar.COLOR_ADDR.value:
                return self.parse_color_addr()
            else:
                return self.parse_color_node()
        elif byte == ControlChar.COLOR_INV.value:
            raise NotImplementedError('COLOR_INV is not supported')
        else:
            return self.parse_text()

    def parse_color_node(self) -> ColorNode:
        """Parse a colored node: COLOR_ON color_tag content* COLOR_OFF color_tag."""
        # Parse COLOR_ON
        if self.consume() != ControlChar.COLOR_ON.value:
            raise ParseError('Expected COLOR_ON')

        # Parse color tag
        color_byte = self.consume()

        # Parse content until we find matching COLOR_OFF
        content: list[Colors] = []
        while not self.at_end():
            byte = self.peek()
            if byte == ControlChar.COLOR_OFF.value:
                # Check if this is the matching close tag
                if self.peek(1) == color_byte:
                    self.consume()  # consume COLOR_OFF
                    self.consume()  # consume color tag
                    return ColorNode(color=color_byte, content=content)

            item = self.parse_content()
            if item is not None:
                content.append(item)

        raise ParseError('Unclosed color tag')

    def parse_color_addr(self) -> ColorAddr:
        """Parse a color address: COLOR_ON COLOR_ADDR addr_bytes text."""
        # Consume COLOR_ON and COLOR_ADDR
        if self.consume() != ControlChar.COLOR_ON.value or self.consume() != ControlChar.COLOR_ADDR.value:
            raise ParseError('Expected COLOR_ON COLOR_ADDR')

        # Parse address bytes (hex string)
        addr_hex = self.consume_bytes(self.address_size.value)
        try:
            addr = int(addr_hex, 16)
        except ValueError:
            raise ParseError(f'Invalid hex address: {addr_hex}') from None

        # Parse text until COLOR_OFF or another control character
        text = self.parse_addr_text()

        return ColorAddr(addr=addr, text=text)

    def parse_addr_text(self) -> str:
        """Parse text following an address (until control character)."""
        chars = []
        control_chars = {
            ControlChar.COLOR_ON.value,
            ControlChar.COLOR_OFF.value,
            ControlChar.COLOR_ESC.value,
            ControlChar.COLOR_INV.value,
        }
        while not self.at_end():
            byte = self.peek()
            if byte in control_chars:
                break
            if byte == ControlChar.COLOR_ESC.value:
                self.consume()
                if not self.at_end():
                    chars.append(chr(self.consume()))
            else:
                chars.append(chr(self.consume()))
        return ''.join(chars)

    def parse_text(self) -> str | None:
        """Parse plain text (non-control characters with escaping)."""
        chars = []
        control_chars = {
            ControlChar.COLOR_ON.value,
            ControlChar.COLOR_OFF.value,
            ControlChar.COLOR_INV.value,
        }
        while not self.at_end():
            byte = self.peek()
            if byte in control_chars:
                break
            if byte == ControlChar.COLOR_ESC.value:
                self.consume()
                if not self.at_end():
                    chars.append(chr(self.consume()))
            else:
                chars.append(chr(self.consume()))

        return ''.join(chars) if chars else None


class ColorParser:
    """Parser for IDA Pro colored strings with configurable address size."""

    def __init__(self, address_size: AddressSize = AddressSize.BITS_64):
        self.address_size = address_size

    def parse(self, s: str) -> ColorNode:
        """Parse colored string."""
        parser = ColorStringParser(s, self.address_size)
        return parser.parse_colored_string()

    def parse_full(self, s: str) -> Colors:
        """Parse a colored string and simplify it."""
        colors = self.parse(s)
        colors = simplify_color_tree(colors)
        return colors


# --------------------
# Main Parser
# --------------------


def parse_colored_string(s: str, address_size: AddressSize = AddressSize.BITS_64) -> ColorNode:
    """Parse colored string."""
    parser = ColorParser(address_size)
    return parser.parse(s)


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

            return f'{"  " * indent}{color_name}\n' + '\n'.join([pp(c, indent + 1, level + 1) for c in content])
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
