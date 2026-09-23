# IDA Colors

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

The CLI needs IDA 9+ and the `ida` extra (`idapro`). The parser itself has no IDA dependency.

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