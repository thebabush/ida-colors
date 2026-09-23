import json
from typing import Any

from ida_colors.color_parser import ColorAddr, ColorNode, Colors, ColorTag, UnknownColorError

# A node mapped by to_json(): a string, or a dict for a ColorNode or ColorAddr.
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


def to_json(node: Colors, hex_addrs: bool = False) -> JsonNode:
    """Map a node to a JSON-able value, e.g. `{"tag": "REG", "children": ["rax"]}`."""
    match node:
        case ColorNode(color=color, content=content):
            tag: str | int | None
            if color is None:
                tag = None
            else:
                # Newer IDA versions add tags, so keep an unknown one as its number.
                try:
                    tag = ColorTag.from_int(color).name
                except UnknownColorError:
                    tag = color
            return {'tag': tag, 'children': [to_json(c, hex_addrs) for c in content]}
        case ColorAddr(addr=addr, text=text):
            return {'addr': format_addr(addr, hex_addrs), 'text': text}
        case str():
            return node
        case _:
            raise ValueError(f'Unknown node: {node}')
