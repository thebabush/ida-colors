import argparse
import atexit
import json
import sys

import idapro  # isort: skip
import ida_auto
import ida_lines
import ida_name
import idautils

from ida_colors import color_parser, pretty


class RoundtripError(Exception):
    """The color parser's tag_remove disagrees with ida_lines'."""


def check_roundtrip(addr: int, raw_asm: str, colors: color_parser.Colors) -> None:
    """Check that color parser's tag_remove is equivalent to ida_lines'."""

    my_raw_asm = color_parser.tag_remove(colors)
    if raw_asm != my_raw_asm:
        raise RoundtripError(f'{addr:08X}: ida_lines.tag_remove gave {raw_asm!r}, color_parser gave {my_raw_asm!r}')


def process_insn(addr: int, strict: bool) -> None:
    asm = ida_lines.generate_disasm_line(addr)
    print(f'{addr:08X}:', asm.encode('utf-8').hex())
    raw_asm = ida_lines.tag_remove(asm)
    colors = color_parser.parse_full(asm)
    if strict:
        check_roundtrip(addr, raw_asm, colors)
    print(f'    {json.dumps(raw_asm)}')
    for line in pretty.format_line(colors):
        print(f'        {line}')
    print()


def process_insn_json(addr: int, func_name: str, strict: bool, hex_addrs: bool) -> None:
    """Print one instruction as a compact JSON object on its own line."""
    asm = ida_lines.generate_disasm_line(addr)
    raw_asm = ida_lines.tag_remove(asm)
    # Not parse_full(), so the tree is always the list of the root's children.
    root = color_parser.parse_colored_string(asm)
    if strict:
        check_roundtrip(addr, raw_asm, root)
    record = {
        'ea': pretty.format_addr(addr, hex_addrs),
        'func': func_name,
        'text': raw_asm,
        'tree': [pretty.to_json(c, hex_addrs) for c in root.content],
    }
    print(json.dumps(record, separators=(',', ':')))


def main(idb_path: str, strict: bool, as_json: bool, hex_addrs: bool) -> None:
    if (err := idapro.open_database(idb_path, False)) != 0:
        sys.exit(f'ida-colors: cannot open {idb_path!r} (open_database returned {err})')
    ida_auto.auto_wait()
    atexit.register(idapro.close_database)

    for func_ea in idautils.Functions():
        name = ida_name.get_name(func_ea)
        if not name:
            name = f'sub_{func_ea:08X}'

        if not as_json:
            print(f'{func_ea:08X}: {name}')

        for chunk_beg, chunk_end in idautils.Chunks(func_ea):
            for addr in idautils.Heads(chunk_beg, chunk_end):
                if as_json:
                    process_insn_json(addr, name, strict, hex_addrs)
                else:
                    process_insn(addr, strict)


def cli() -> None:
    parser = argparse.ArgumentParser(prog='ida-colors', description='Dump the parsed color tags of every instruction.')
    parser.add_argument('idb_path', help='IDA database (or binary) to open')
    parser.add_argument(
        '--strict', action='store_true', help="fail if the parser's tag_remove disagrees with IDA's on any line"
    )
    parser.add_argument('--json', action='store_true', help='print one JSON object per instruction (JSON Lines)')
    parser.add_argument('--hex', action='store_true', help='with --json, print addresses as hex strings')
    args = parser.parse_args()
    if args.hex and not args.json:
        parser.error('--hex requires --json')
    try:
        main(args.idb_path, args.strict, args.json, args.hex)
    except RoundtripError as e:
        sys.exit(f'ida-colors: {e}')


if __name__ == '__main__':
    cli()
