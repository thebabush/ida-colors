"""Differential test of ida_colors against ida_colors_ref, a frozen copy of it, on real and mangled lines.

Any change to the parser, numbers() or strings() that is meant to keep behavior, e.g. a speedup, must keep these
passing. The two packages have distinct classes, so results are compared as plain tuples.
"""

import json
import random
from collections.abc import Callable, Sequence
from dataclasses import astuple
from pathlib import Path
from types import ModuleType
from typing import TypeAlias

import pytest

import ida_colors as live
import ida_colors_ref as ref
from ida_colors._compat import assert_never

LINES: dict[str, list[str]] = json.loads((Path(__file__).parent / 'data' / 'lines.json').read_text())
SIZES = ['BITS_64', 'BITS_32']

# Hand-written edge cases from test_color_parser.py, as extra seeds for mutation.
EDGE_CASES = [
    '\x01)\x01!rsp\x02!\x02)',
    '\x01\x05nop\x02\x05 x',
    '\x01)\x01!cs\x02!\x01\t:\x02\t\x01\x06\x01(00000000008604D8off_8604D8\x02\x06\x02)',
    (
        '\x01\x13.text:000000000001EE40\x02\x13 \x01\x02;\x02\x02 \x01 __unwind\x02  \x01\t{\x02\t '
        '\x01\x02// \x01"\x01(0000000000083700__gxx_personality_v0\x02"\x02\x02\x02\x02'
    ),
    'a\x02\x05b',
    'a\x03\x01b\x03',
    '\x01(0000000000001234ab\x03!c',
    'a\x04b',
    '\x04\x04\x01\t}\x02\t\x01(0000000000000000',
    '\x01\x04x\x02\x04',
    '\x01\x36\x01\x01\x25name\x02\x25\x02\x36',
    '\x01\x36\x03000000000000abcdFoo\x02\x36',
    '\x01\x36\x030000abcdFoo\x02\x36',
    '\x01\x05\x01\x06a\x02\x05\x02\x06',
    '\x01(0000_00000001234',
]

# Control chars, then ADDR and SEMSPAN tag bytes, then hex digits, a non-hex letter and some non-ASCII.
SPECIAL = ['\x01', '\x02', '\x03', '\x04', '(', '6', '0', 'a', 'F', 'g', '"', "'", ';', ' ', '\xff', '\u2603']

MUTATION_CHUNKS = 8
MUTATIONS_PER_CHUNK = 4000

Norm: TypeAlias = 'str | int | bool | tuple[Norm, ...] | None'
Outcome: TypeAlias = tuple[str, Norm]


def _tree(node: live.Colors | ref.Colors) -> Norm:
    match node:
        case live.ColorNode(color=color, content=content) | ref.ColorNode(color=color, content=content):
            return ('node', color, tuple(_tree(child) for child in content))
        case live.ColorAddr(addr=addr, text=text) | ref.ColorAddr(addr=addr, text=text):
            return ('addr', addr, text)
        case str():
            return node
        case _:
            assert_never(node)


def _record(value: live.Number | live.String | ref.Number | ref.String) -> Norm:
    return (type(value).__name__, *astuple(value))


# What each implementation's functions make of its own parse_full tree.
STEPS: dict[str, Callable[[ModuleType, live.Colors | ref.Colors], Norm]] = {
    'tag_remove': lambda impl, tree: impl.tag_remove(tree),
    'iter_nodes': lambda impl, tree: tuple(_tree(node) for node in impl.iter_nodes(tree)),
    'numbers': lambda impl, tree: tuple(_record(n) for n in impl.numbers(tree)),
    'strings': lambda impl, tree: tuple(_record(s) for s in impl.strings(tree)),
}


def _pipeline(impl: ModuleType, line: str, size: str) -> list[tuple[str, Outcome]]:
    """Run every step on the implementation's own trees, so each side is checked end to end."""
    address_size = impl.AddressSize[size]
    out: list[tuple[str, Outcome]] = []
    try:
        tree = impl.parse_colored_string(line, address_size)
        out += [
            ('parse_colored_string', ('ok', _tree(tree))),
            ('simplify_color_tree', ('ok', _tree(impl.simplify_color_tree(tree)))),
        ]
        tree = impl.parse_full(line, address_size)
        out.append(('parse_full', ('ok', _tree(tree))))
        for step, run in STEPS.items():
            out.append((step, ('ok', run(impl, tree))))
    except Exception as e:
        out.append(('raise', (type(e).__name__, str(e))))
    return out


def _mismatch(line: str, size: str) -> tuple[str | None, bool]:
    """Describe the first result that differs between live and ref, if any, and tell whether the parse raised."""
    got, want = _pipeline(live, line, size), _pipeline(ref, line, size)
    raised = want[0][0] == 'raise'
    for (step, g), (ref_step, w) in zip(got, want, strict=False):
        if (step, g) != (ref_step, w):
            where = step if step == ref_step else f'live {step} vs ref {ref_step}'
            return f'{where} on {line[:200]!r} ({size}):\n  live: {g!r}\n  ref:  {w!r}', raised
    if len(got) != len(want):
        return f'{line[:200]!r} ({size}): live ran {[s for s, _ in got]}, ref ran {[s for s, _ in want]}', raised
    return None, raised


def _check(cases: Sequence[tuple[str, str]]) -> int:
    """Assert live and ref agree on every (line, size). Return how many cases had the parse raise."""
    errors = 0
    for line, size in cases:
        diff, raised = _mismatch(line, size)
        assert diff is None, diff
        errors += raised
    return errors


def _mutate(rng: random.Random, line: str, pool: Sequence[str]) -> str:
    for _ in range(rng.randint(1, 3)):
        i, j = sorted(rng.randrange(len(line) + 1) for _ in range(2))
        k = rng.randrange(len(line) + 1)
        match rng.randrange(7):
            case 0:
                line = line[:i]
            case 1:
                line = line[:i] + line[i + rng.randint(1, 4) :]
            case 2:
                line = line[:k] + rng.choice(SPECIAL) + line[k:]
            case 3:
                line = line[:k] + rng.choice(SPECIAL) + line[k + 1 :]
            case 4:
                # Any tag byte, known or not, right after an ON or OFF.
                tag = chr(rng.choice([rng.randrange(0x80), 0xFF, 0x2603]))
                line = line[:k] + rng.choice('\x01\x02') + tag + line[k:]
            case 5:
                line = line[:k] + line[i:j] + line[k:]
            case _:
                # Swap two adjacent segments, or splice in the tail of another line.
                if rng.random() < 0.5:
                    line = line[:i] + line[j:k] + line[i:j] + line[k:] if k > j else line[i:j] + line[:i] + line[j:]
                else:
                    other = rng.choice(pool)
                    line = line[:i] + other[rng.randrange(len(other) + 1) :]
    return line


def test_ref_is_a_separate_copy() -> None:
    # Guards against the oracle silently comparing the live package to itself.
    assert ref.ColorNode is not live.ColorNode
    assert ref.parse_colored_string.__module__ == 'ida_colors_ref.color_parser'


@pytest.mark.parametrize('size', SIZES)
@pytest.mark.parametrize('proc', LINES)
def test_real_lines(proc: str, size: str) -> None:
    _check([(line, size) for line in LINES[proc]])


def test_edge_cases() -> None:
    _check([(line, size) for line in EDGE_CASES for size in SIZES])


@pytest.mark.parametrize('seed', range(MUTATION_CHUNKS))
def test_mutated_lines(seed: int) -> None:
    rng = random.Random(seed)
    pool = [line for lines in LINES.values() for line in lines]
    cases = [
        # One in ten starts from an edge case, which would otherwise be lost among the real lines.
        (_mutate(rng, rng.choice(EDGE_CASES if rng.random() < 0.1 else pool), pool), rng.choice(SIZES))
        for _ in range(MUTATIONS_PER_CHUNK)
    ]
    errors = _check(cases)
    # Both the error path and the success path must get real coverage, or the mutations are too weak or too strong.
    assert len(cases) // 10 < errors < len(cases) * 9 // 10


def test_oracle_detects_a_different_result(monkeypatch: pytest.MonkeyPatch) -> None:
    line = LINES['amd64'][0]
    assert _mismatch(line, 'BITS_64') == (None, False)
    monkeypatch.setattr(live, 'tag_remove', lambda node: '')
    diff, _ = _mismatch(line, 'BITS_64')
    assert diff is not None
    assert diff.startswith('tag_remove on ')


def test_oracle_detects_a_different_error(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _mismatch('\x01', 'BITS_64') == (None, True)

    def parse(s: str, address_size: live.AddressSize = live.AddressSize.BITS_64) -> live.ColorNode:
        raise live.ParseError('Truncated input')

    monkeypatch.setattr(live, 'parse_colored_string', parse)
    diff, _ = _mismatch('\x01', 'BITS_64')
    assert diff is not None
    assert "'Truncated input'" in diff
