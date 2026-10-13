"""Integer values of the numbers in a parsed line, as IDA printed them."""

import re
from collections.abc import Sequence
from dataclasses import dataclass

from ida_colors.color_parser import ColorNode, Colors, ColorTag, tag_remove

# Decimal without a leading 0 (some assemblers read 010 as octal), 0x-prefixed hex, or h-suffixed hex that starts with
# a digit (IDA adds a 0 when it would start with a letter, otherwise it reads as a name).
_INT = re.compile(r'(?P<dec>0|[1-9][0-9]*)|0x(?P<hex>[0-9A-Fa-f]+)|(?P<hex_h>[0-9][0-9A-Fa-f]*)h')

_SYMBOL = ColorTag.SYMBOL.value
_NUMBER_TAGS = frozenset({ColorTag.NUMBER.value, ColorTag.DNUM.value})
_OPERAND_TAGS = {tag.value: int(tag.name[4:]) for tag in ColorTag if tag.name.startswith('OPND')}

# Symbols that can stand next to a number that is a whole operand, e.g. `#0x10`, `-1`, `=0xCBF29CE4`.
_PREFIX_CHARS = frozenset('#=-')


def parse_int(text: str) -> int | None:
    """Return the value of a number's spelling, or None when it's not one of IDA's plain integer spellings."""
    if (m := _INT.fullmatch(text)) is None:
        return None
    if (dec := m['dec']) is not None:
        return int(dec)
    return int(m['hex'] or m['hex_h'], 16)


def _fit(value: int, bits: int, signed: bool) -> int | None:
    # Two's complement reinterpretation, so -1 is 0xFFFFFFFF in 32 bits and vice versa. None when it doesn't fit.
    if not -(1 << (bits - 1)) <= value < 1 << bits:
        return None
    value &= (1 << bits) - 1
    if signed and value >> (bits - 1):
        value -= 1 << bits
    return value


@dataclass(frozen=True, slots=True)
class Number:
    """A number in a line, with the `-` printed in front of it applied."""

    value: int
    # The operand it's in, 1 to 8, or None outside operands (e.g. in a comment).
    operand: int | None
    # True when the number is the entire operand, give or take a `#`, `=` or `-`. E.g. `#0x10` and `-1` are, while
    # `[X1,#0x10]` and `0x10+var_10` are not.
    standalone: bool

    def u8(self) -> int | None:
        return _fit(self.value, 8, signed=False)

    def u16(self) -> int | None:
        return _fit(self.value, 16, signed=False)

    def u32(self) -> int | None:
        return _fit(self.value, 32, signed=False)

    def u64(self) -> int | None:
        return _fit(self.value, 64, signed=False)

    def i8(self) -> int | None:
        return _fit(self.value, 8, signed=True)

    def i16(self) -> int | None:
        return _fit(self.value, 16, signed=True)

    def i32(self) -> int | None:
        return _fit(self.value, 32, signed=True)

    def i64(self) -> int | None:
        return _fit(self.value, 64, signed=True)


def _is_symbol(node: Colors) -> bool:
    return isinstance(node, ColorNode) and node.color == _SYMBOL


def _is_blank(node: Colors) -> bool:
    return isinstance(node, str) and not node.strip()


def _is_negated(siblings: Sequence[Colors], index: int) -> bool:
    # The sign is never in the token: it ends the symbol before it, e.g. `-`, `,#-` or `*4-` but not `#-(`.
    for prev in reversed(siblings[:index]):
        if not _is_blank(prev):
            return _is_symbol(prev) and tag_remove(prev).rstrip().endswith('-')
    return False


def _is_standalone(siblings: Sequence[Colors], index: int) -> bool:
    return all(
        i == index or _is_blank(node) or (_is_symbol(node) and _PREFIX_CHARS.issuperset(tag_remove(node).strip()))
        for i, node in enumerate(siblings)
    )


def _walk(node: ColorNode, operand: int | None, out: list[Number]) -> None:
    operand = _OPERAND_TAGS.get(node.color, operand)
    for i, child in enumerate(node.content):
        if not isinstance(child, ColorNode):
            continue
        if child.color not in _NUMBER_TAGS:
            _walk(child, operand, out)
        elif (value := parse_int(tag_remove(child))) is not None:
            out.append(
                Number(
                    value=-value if _is_negated(node.content, i) else value,
                    operand=operand,
                    # Only a direct child of the operand can be the whole operand.
                    standalone=node.color in _OPERAND_TAGS and _is_standalone(node.content, i),
                )
            )


def numbers(tree: Colors) -> list[Number]:
    """Return the integers in a parsed line, in order. Floats and spellings that aren't plain integers are skipped."""
    out: list[Number] = []
    if isinstance(tree, ColorNode):
        _walk(tree, None, out)
    return out
