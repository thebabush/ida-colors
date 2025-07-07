# IDA Colors

Parser for color tags in IDA.

## Usage

```sh
$ uv run python -m ida_colors <path-to-idb>
...
    "LDR             X8, [X19,#0x10]"
        Insn("LDR")
        Opnd1(Reg("X8"))
        Opnd2(Symbol("["), Reg("X19"), Symbol(",#"), Number("0x10"), Symbol("]"))
...
```

## Why?

Simple-ish way to get some minimal tokenization/parsing of the IDA disassembly.