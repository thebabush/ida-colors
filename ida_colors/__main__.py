import argparse
import atexit
import json
from collections.abc import Iterable

import idapro  # isort: skip
import ida_auto
import ida_lines
import ida_name
import idautils

from ida_colors import color_parser


def check_roundtrip(tagged_asm: str) -> tuple[str, color_parser.Colors]:
    """Check that color parser's tag_remove is equivalent to ida_lines'."""

    raw_asm = ida_lines.tag_remove(tagged_asm)
    colors = color_parser.parse_full(tagged_asm)
    my_raw_asm = color_parser.tag_remove(colors)

    assert raw_asm == my_raw_asm

    return raw_asm, colors


def process_insn(addr: int) -> None:
    asm = ida_lines.generate_disasm_line(addr)
    print(f'{addr:08X}:', asm.encode('ascii').hex())
    raw_asm, colors = check_roundtrip(asm)
    print(f'    {json.dumps(raw_asm)}')
    for line in pp(colors):
        print(f'        {line}')
    print()


def pp(colors: color_parser.Colors) -> Iterable[str]:
    """Pretty print a colored string."""
    assert isinstance(colors, color_parser.ColorNode)
    mnemonic, *operands = colors.content
    if operands:
        assert colors.color is None

    yield ''.join(_pp(mnemonic))
    for operand in operands:
        match operand:
            case str() if not operand.strip():
                continue
            case color_parser.ColorNode(color=ida_lines.COLOR_SYMBOL, content=[',']):
                continue
        yield ''.join(_pp(operand))


def _pp(colors: color_parser.Colors) -> Iterable[str]:
    """Pretty print a colored string."""
    match colors:
        case color_parser.ColorNode(color=color, content=content):
            color_name = color_parser.ColorTag.from_int(color).name.title() if color is not None else '_'
            # Skip whitespace-only strings
            children = [''.join(_pp(c)) for c in content if not (isinstance(c, str) and not c.strip())]
            yield f'{color_name}({", ".join(children)})'

        case color_parser.ColorAddr(addr=addr, text=text):
            yield f'Addr({addr:08X}, {text!r})'
        case str():
            yield f'{json.dumps(colors)}'
        case _:
            raise ValueError(f'Unknown node: {colors}')


def main(idb_path: str) -> None:
    idapro.open_database(idb_path, False)
    ida_auto.auto_wait()
    atexit.register(idapro.close_database)

    for func_ea in idautils.Functions():
        print(f'{func_ea:08X}: ', end='')

        name = ida_name.get_name(func_ea)
        if not name:
            name = f'sub_{func_ea:08X}'

        print(name)

        for chunk_beg, chunk_end in idautils.Chunks(func_ea):
            for addr in idautils.Heads(chunk_beg, chunk_end):
                process_insn(addr)


def cli() -> None:
    parser = argparse.ArgumentParser(prog='ida-colors', description='Dump the parsed color tags of every instruction.')
    parser.add_argument('idb_path', help='IDA database (or binary) to open')
    main(parser.parse_args().idb_path)


if __name__ == '__main__':
    cli()
