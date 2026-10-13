"""Micro benchmark of parse_full, numbers and strings over the real lines in tests/data/lines.json.

Run it with `uv run python bench/bench.py`. Each stage runs over every line of a processor once per repeat, and the
best repeat is reported in microseconds per line.
"""

import argparse
import json
import timeit
from collections.abc import Callable
from functools import partial
from pathlib import Path

from ida_colors import Colors, numbers, parse_full, strings

FIXTURE = Path(__file__).resolve().parent.parent / 'tests' / 'data' / 'lines.json'


def _parse(lines: list[str], trees: list[Colors]) -> None:
    for line in lines:
        parse_full(line)


def _numbers(lines: list[str], trees: list[Colors]) -> None:
    for tree in trees:
        numbers(tree)


def _strings(lines: list[str], trees: list[Colors]) -> None:
    for tree in trees:
        strings(tree)


def _pipeline(lines: list[str], trees: list[Colors]) -> None:
    for line in lines:
        tree = parse_full(line)
        numbers(tree)
        strings(tree)


# numbers and strings run over trees parsed up front, so they don't pay for parsing. pipeline does all three per line.
STAGES: dict[str, Callable[[list[str], list[Colors]], None]] = {
    'parse_full': _parse,
    'numbers': _numbers,
    'strings': _strings,
    'pipeline': _pipeline,
}


def _load(path: Path) -> dict[str, list[str]]:
    data = json.loads(path.read_text())
    if not (
        isinstance(data, dict)
        and all(isinstance(lines, list) and all(isinstance(line, str) for line in lines) for lines in data.values())
    ):
        raise SystemExit(f'{path}: expected a JSON object of processor name to a list of tagged lines')
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description='Time parse_full, numbers and strings per line of real disassembly.')
    parser.add_argument('-n', '--repeat', type=int, default=10, help='runs per stage, the best one counts (default 10)')
    parser.add_argument(
        '-s', '--stage', action='append', choices=STAGES, help='stage to time, repeatable (all by default)'
    )
    parser.add_argument('--fixture', type=Path, default=FIXTURE, help='JSON object of processor name to tagged lines')
    args = parser.parse_args()
    stages: list[str] = args.stage or list(STAGES)

    data = _load(args.fixture)
    best: dict[str, dict[str, float]] = {}
    for proc, lines in data.items():
        trees = [parse_full(line) for line in lines]
        best[proc] = {
            stage: min(timeit.repeat(partial(STAGES[stage], lines, trees), number=1, repeat=args.repeat))
            for stage in stages
        }

    # The total row is the sum of the per-processor bests over all lines.
    width = max(len(name) for name in [*data, 'µs/line', 'total'])
    print(f'{"µs/line":<{width}} {"lines":>6}' + ''.join(f' {stage:>10}' for stage in stages))
    rows = [(proc, len(lines), best[proc]) for proc, lines in data.items()]
    total = {stage: sum(times[stage] for times in best.values()) for stage in stages}
    rows.append(('total', sum(len(lines) for lines in data.values()), total))
    for name, count, times in rows:
        print(f'{name:<{width}} {count:>6}' + ''.join(f' {times[stage] / count * 1e6:>10.2f}' for stage in stages))


if __name__ == '__main__':
    main()
