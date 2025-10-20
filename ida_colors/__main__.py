import atexit
import json
import sys
from typing import Iterable

import idapro  # noqa: F401 # isort: skip
import ida_auto
import ida_funcs
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
    raw_asm, colors = check_roundtrip(asm)
    print(f'    {json.dumps(raw_asm)}')
    for line in pp(colors):
        print(f'        {line}')
    print()


def pp(colors: color_parser.Colors) -> Iterable[str]:
    """Pretty print a colored string."""
    assert isinstance(colors, color_parser.ColorNode)
    mnemonic, *operands = colors.content

    if len(operands) > 0:
        assert colors.color is None
        yield ''.join(_pp(mnemonic))
        for operand in operands:
            match operand:
                case color_parser.ColorNode(color=None, content=[str()]):
                    # Skip whitespaces
                    assert isinstance(operand.content[0], str)
                    if not operand.content[0].strip():
                        continue
                case color_parser.ColorNode(color=ida_lines.COLOR_SYMBOL, content=[',']):
                    continue
            yield ''.join(_pp(operand))
    else:
        yield ''.join(_pp(mnemonic))


def _pp(colors: color_parser.Colors) -> Iterable[str]:
    """Pretty print a colored string."""
    match colors:
        case color_parser.ColorNode(color=color, content=content):
            if color is not None:
                color_name = color_parser.ColorTag.from_int(color).name.title()
            else:
                color_name = '_'
            yield f'{color_name}('

            tokens = [_pp(c) for c in content]
            for ith, token in enumerate(tokens):
                yield from token
                if ith < len(tokens) - 1:
                    yield ', '

            yield ')'

        case color_parser.ColorAddr(addr=addr, text=text):
            yield f'Addr({addr:08X}, {repr(text)})'
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

        funk = ida_funcs.get_func(func_ea)
        if not funk:
            print('no function :(')
            continue

        name = ida_name.get_name(func_ea)
        if not name:
            name = f'sub_{func_ea:08X}'

        print(name)

        for chunk_beg, chunk_end in idautils.Chunks(func_ea):
            for addr in idautils.Heads(chunk_beg, chunk_end):
                process_insn(addr)


if __name__ == '__main__':
    main(*sys.argv[1:])
