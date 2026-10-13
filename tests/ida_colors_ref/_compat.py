# Frozen copy of ida_colors at commit cadd518, used as the oracle for behavior-preserving changes. Do not edit.
from typing import NoReturn


def assert_never(value: NoReturn) -> NoReturn:
    """End a match that must be exhaustive. ty reports any case left unhandled.

    Same as typing.assert_never, which needs Python 3.11.
    """
    raise AssertionError(f'Unhandled value: {value!r}')
