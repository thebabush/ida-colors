# IDA Colors

[![CI](https://github.com/thebabush/ida-colors/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/thebabush/ida-colors/actions/workflows/ci.yml?query=branch%3Amaster)

Parser for color tags in IDA.

## Usage

```sh
$ uv run ida-colors <path-to-idb>
...
    "LDR             X8, [X19,#0x10]"
        Insn("LDR")
        Opnd1(Reg("X8"))
        Opnd2(Symbol("["), Reg("X19"), Symbol(",#"), Number("0x10"), Symbol("]"))
...
```

`--json` prints one JSON object per instruction instead, for scripts and agents (`--hex` makes addresses hex strings):

```sh
$ uv run ida-colors --json <path-to-idb>
{"ea":"4294973168","func":"sub_1000016F0","text":"push    rbp","tree":[{"tag":"INSN","children":["push"]},"    ",{"tag":"OPND1","children":[{"tag":"REG","children":["rbp"]}]}]}
```

The CLI needs IDA 9+ and the `ida` extra (`idapro`). The parser itself has no dependencies.

## Development

```sh
$ uv run ruff check && uv run ruff format --check
$ uv run ty check
$ uv run pytest
```

`tests/test_ida_constants.py` checks the constants copied from IDA against a local IDA install, and is
skipped when `idapro` can't load one.

## Why?

Simple-ish way to get some minimal tokenization/parsing of the IDA disassembly.