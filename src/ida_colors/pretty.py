import json
from typing import Any

from ida_colors.color_parser import ColorAddr, ColorNode, Colors, ColorTag, UnknownColorError

# An item from to_json_items(): a string, or a single-key dict for a ColorNode or a ColorAddr's address.
JsonNode = str | dict[str, Any]


def format_line(colors: Colors) -> list[str]:
    """Format a parsed line as its mnemonic followed by each operand."""
    # parse_full() unwraps a line that is a single colored node, e.g. a bare `nop`.
    parts = colors.content if isinstance(colors, ColorNode) and colors.color is None else [colors]
    if not parts:
        return []
    mnemonic, *operands = parts

    lines = [format_node(mnemonic)]
    for operand in operands:
        match operand:
            case str() if not operand.strip():
                continue
            case ColorNode(color=ColorTag.SYMBOL.value, content=[',']):
                continue
        lines.append(format_node(operand))
    return lines


def format_node(node: Colors) -> str:
    """Format a node as e.g. `Opnd2(Reg("rbx"))`."""
    match node:
        case ColorNode(color=color, content=content):
            color_name = ColorTag.from_int(color).name.title() if color is not None else '_'
            # Skip whitespace-only strings
            children = [format_node(c) for c in content if not (isinstance(c, str) and not c.strip())]
            return f'{color_name}({", ".join(children)})'
        case ColorAddr(addr=addr, text=text):
            return f'Addr({addr:08X}, {text!r})'
        case str():
            return json.dumps(node)
        case _:
            raise ValueError(f'Unknown node: {node}')


def format_addr(addr: int, hex_addrs: bool = False) -> str:
    """Format an address for JSON output, as a decimal string or a `0x`-prefixed hex string."""
    return hex(addr) if hex_addrs else str(addr)


def to_json_items(node: Colors, hex_addrs: bool = False) -> list[JsonNode]:
    """Map a node to the JSON-able items it contributes to its parent's list, e.g. `[{"REG": ["rax"]}]`.

    A ColorAddr gives two items, `{"ADDR": addr}` then its text (if any), like the raw address mark does.
    """
    match node:
        case ColorNode(color=color, content=content):
            if color is None:
                tag = '_'
            else:
                # Newer IDA versions add tags, so keep an unknown one as its number.
                try:
                    tag = ColorTag.from_int(color).name
                except UnknownColorError:
                    tag = str(color)
            return [{tag: [item for c in content for item in to_json_items(c, hex_addrs)]}]
        case ColorAddr(addr=addr, text=text):
            items: list[JsonNode] = [{'ADDR': format_addr(addr, hex_addrs)}]
            if text:
                items.append(text)
            return items
        case str():
            return [node]
        case _:
            raise ValueError(f'Unknown node: {node}')
