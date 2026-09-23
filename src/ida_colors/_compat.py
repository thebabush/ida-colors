from typing import NoReturn


def assert_never(value: NoReturn) -> NoReturn:
    """End a match that must be exhaustive. ty reports any case left unhandled.

    Same as typing.assert_never, which needs Python 3.11.
    """
    raise AssertionError(f'Unhandled value: {value!r}')
