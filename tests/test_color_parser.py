import json
from typing import Any

from pydantic import BaseModel

from ida_colors.color_parser import (
    ColorAddr,
    ColorNode,
    Colors,
    ColorTag,
    lift_ast,
    parse_colored_string,
    simplify_color_tree,
)


def parse_lift(s: str) -> Colors:
    tree = parse_colored_string(s)
    print(tree)
    return lift_ast(tree)


def dump_with_types(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        cls = obj.__class__
        result = {'_': cls.__name__}
        for field in obj.__class__.model_fields:
            if field == 'color' and getattr(obj, 'color', None) is not None:
                color_val = getattr(obj, 'color')
                result[field] = ColorTag.from_int(color_val).name
            else:
                result[field] = dump_with_types(getattr(obj, field))
        return result

    elif isinstance(obj, list):
        return [dump_with_types(item) for item in obj]

    elif isinstance(obj, dict):
        return {k: dump_with_types(v) for k, v in obj.items()}

    else:
        return obj  # base types (str, int, etc.)


def test_parse_colored_string_easy() -> None:
    raw = '\x01)\x01!rsp\x02!\x02)'
    parse_lift(raw)


def test_parse_colored_string_addr() -> None:
    raw = '\x01)\x01!cs\x02!\x01\t:\x02\t\x01\x06\x01(00000000008604D8off_8604D8\x02\x06\x02)'
    tree = parse_lift(raw)
    print(json.dumps(dump_with_types(tree), indent=2))
    target = ColorNode(
        color=None,
        content=[
            ColorNode(
                color=41,
                content=[
                    ColorNode(
                        color=None,
                        content=[
                            ColorNode(color=33, content=[ColorNode(color=None, content=['cs'])])
                        ],
                    ),
                    ColorNode(
                        color=None,
                        content=[
                            ColorNode(color=9, content=[ColorNode(color=None, content=[':'])])
                        ],
                    ),
                    ColorNode(
                        color=None,
                        content=[
                            ColorNode(
                                color=6,
                                content=[
                                    ColorNode(
                                        color=None,
                                        content=[ColorAddr(addr=8783064, text='off_8604D8')],
                                    )
                                ],
                            )
                        ],
                    ),
                ],
            )
        ],
    )
    assert tree == target

    tree = simplify_color_tree(tree)
    dump_with_types(tree)
    simplify_target = ColorNode(
        color=41,
        content=[
            ColorNode(color=33, content=['cs']),
            ColorNode(color=9, content=[':']),
            ColorNode(color=6, content=[ColorAddr(addr=8783064, text='off_8604D8')]),
        ],
    )
    assert tree == simplify_target


def test_parse_colored_byte_ptr() -> None:
    raw = '\x01)\x01 byte ptr\x02  \x01\t[\x02\t\x01!rbp\x02!\x01\t+\x02\t\x01\x0c1\x02\x0c\x01\t]\x02\t\x02)'
    colors = parse_lift(raw)
    target = ColorNode(
        color=None,
        content=[
            ColorNode(
                color=41,
                content=[
                    ColorNode(
                        color=None,
                        content=[
                            ColorNode(
                                color=32, content=[ColorNode(color=None, content=['byte ptr'])]
                            )
                        ],
                    ),
                    ColorNode(color=None, content=[' ']),
                    ColorNode(
                        color=None,
                        content=[
                            ColorNode(color=9, content=[ColorNode(color=None, content=['['])])
                        ],
                    ),
                    ColorNode(
                        color=None,
                        content=[
                            ColorNode(color=33, content=[ColorNode(color=None, content=['rbp'])])
                        ],
                    ),
                    ColorNode(
                        color=None,
                        content=[
                            ColorNode(color=9, content=[ColorNode(color=None, content=['+'])])
                        ],
                    ),
                    ColorNode(
                        color=None,
                        content=[
                            ColorNode(color=12, content=[ColorNode(color=None, content=['1'])])
                        ],
                    ),
                    ColorNode(
                        color=None,
                        content=[
                            ColorNode(color=9, content=[ColorNode(color=None, content=[']'])])
                        ],
                    ),
                ],
            )
        ],
    )
    assert colors == target
    colors = simplify_color_tree(colors)
    target = ColorNode(
        color=41,
        content=[
            ColorNode(color=32, content=['byte ptr']),
            ColorNode(color=None, content=[' ']),
            ColorNode(color=9, content=['[']),
            ColorNode(color=33, content=['rbp']),
            ColorNode(color=9, content=['+']),
            ColorNode(color=12, content=['1']),
            ColorNode(color=9, content=[']']),
        ],
    )
    assert colors == target
