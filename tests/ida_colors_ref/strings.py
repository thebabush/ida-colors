# Frozen copy of ida_colors at commit cadd518, used as the oracle for behavior-preserving changes. Do not edit.
"""Strings and chars that IDA shows in the automatic comments of a parsed line."""

import re
from collections.abc import Sequence
from dataclasses import dataclass

from ida_colors_ref.color_parser import ColorAddr, Colors, ColorTag, iter_nodes

# `; ` on most processors, `# ` on PowerPC, RISC-V and s390x, ` # ` on MIPS.
_PREFIX = re.compile(r' ?[;#] ')

# The text is C-escaped, so a `"` inside it is always `\"`. A truncated string ends in `"...`, and one shown through a
# pointer ends in `" ...`. A name has the same shape without the quotes.
_STRING = re.compile(r'"(?P<text>(?:[^"\\]|\\.)*)"(?:(?P<truncated>\.\.\.)| \.\.\.)?', re.DOTALL)

# One or more single chars, each between quotes and not escaped, e.g. `'''` is an apostrophe and `'\'` a backslash.
_CHARS = re.compile(r"'.'(?: '.')*", re.DOTALL)


@dataclass(frozen=True, slots=True)
class String:
    """A string or a char shown in a comment, as printed: escapes are kept, quotes are not."""

    text: str
    # True for a char constant, e.g. `'5'` next to `sub esi, 35h`.
    char: bool
    # Where the string starts, or None for a char.
    addr: int | None
    # True when IDA cut the string short.
    truncated: bool


def _autocmt(content: Sequence[Colors], out: list[String]) -> None:
    match content:
        case [str() as prefix, ColorAddr(addr=addr, text=text)] if _PREFIX.fullmatch(prefix):
            if m := _STRING.fullmatch(text):
                out.append(String(text=m['text'], char=False, addr=addr, truncated=m['truncated'] is not None))
        case [str() as text] if (prefix := _PREFIX.match(text)) and _CHARS.fullmatch(text, prefix.end()):
            # Each char is 3 wide, plus a space between them.
            out.extend(String(text=c, char=True, addr=None, truncated=False) for c in text[prefix.end() + 1 :: 4])
        case _:
            pass


def strings(tree: Colors) -> list[String]:
    """Return the strings and chars in a line's automatic comments, in order. Other comment text is skipped."""
    out: list[String] = []
    for node in iter_nodes(tree):
        if node.color == ColorTag.AUTOCMT.value:
            _autocmt(node.content, out)
    return out
