import json

from ida_colors.color_parser import ColorAddr, ColorNode, Colors, ColorTag


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
