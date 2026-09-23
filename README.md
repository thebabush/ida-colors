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

IDA's disassembly isn't just the decoded instruction. Between `decode_insn` and the line you see, the processor module's
printer applies a lot of heuristics and user annotations: offsets, stack variables, struct offsets, enums, chars,
`@PAGE`/`@PAGEOFF` pairs, hidden implicit operands. The printed line is the only place where all of that comes together,
and IDA marks it up with color tags. Parsing the tags gets you what IDA decided, without reimplementing its printer for
every processor.

The textbook alternative, `decode_insn` and `op_t.type` (`o_imm`, `o_mem`, `o_displ`, ...), tells you what the bytes
encode, not what they mean:

| Instruction | `decode_insn` says | IDA prints |
|---|---|---|
| PowerPC `addis r30, r30, (off_11FA38 - loc_1923C)@ha` | `o_imm`, value `0x10` | the high half of an address difference |
| RISC-V `auipc t2, %pcrel_hi(off_C8380)` | `o_imm`, value `0xbc` | a PC-relative reference to `off_C8380` |
| ARM64 `ADRP X16, #qword_11FFF8@PAGE` | `o_imm`, value `0x11f000` | a reference to `qword_11FFF8` |
| SPARC `add %fp, arg_727, %l1` | `o_imm`, value `0x727` | the stack argument `arg_727` |
| x86-64 `mov [rbp+var_30], rax` | `o_displ`, value `0xffffffffffffffd0` | the stack variable `var_30` |
| x86-64 `lea rdi, ds:1[rdx*2]` | `o_mem`, address `0x1` | a plain number |
| RISC-V `nop` | one operand, `o_imm` | no operands |
| PowerPC `mflr r0` | two operands, the second `o_idpspec0` | one operand |
| x86-64 `mul rcx` | two operands, implicit `rax` first | one operand, tagged as operand 2 |

The parser is checked against every line of every function in Debian's busybox for amd64, i386, arm64, armel, armhf,
mipsel, mips64el, powerpc, ppc64, ppc64el, riscv64, sparc64, s390x, m68k, sh4, hppa and alpha.
