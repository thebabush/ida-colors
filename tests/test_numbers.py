import pytest

from ida_colors.color_parser import parse_full
from ida_colors.numbers import Number, numbers, parse_int


@pytest.mark.parametrize(
    ('text', 'value'),
    [
        ('0', 0),
        ('8', 8),
        ('31', 31),  # MIPS shift amount
        ('30h', 0x30),  # x86, RISC-V
        ('0C0h', 0xC0),  # leading 0 when the first digit is a letter
        ('0FFFFFFFFFFFFFFFFh', 0xFFFFFFFFFFFFFFFF),
        ('00000000h', 0),  # x86 nop padding, tagged DNUM
        ('0x10', 0x10),  # ARM, MIPS, PowerPC, s390x
        ('0xFFFFFFFF84222325', 0xFFFFFFFF84222325),
    ],
)
def test_parse_int(text: str, value: int) -> None:
    assert parse_int(text) == value


@pytest.mark.parametrize(
    'text',
    [
        '0.25',  # ARM FMOV
        '-20.0',  # a float, the only token seen with the sign inside
        '-8',
        '+8',
        ' 8',
        '',
        'h',
        '0x',
        'C0h',  # no leading 0: a name, not a number
        '010',  # octal in some assemblers
        '101b',  # binary
        '17o',  # octal
        "'A'",  # char
        '1_0',
        '0X10',
    ],
)
def test_parse_int_unknown(text: str) -> None:
    assert parse_int(text) is None


def _numbers(raw: str) -> list[Number]:
    return numbers(parse_full(raw))


def test_immediate() -> None:
    # MOV X0, #0x10
    raw = '\x01\x05MOV\x02\x05 \x01)\x01!X0\x02!\x02)\x01\t,\x02\t \x01*\x01\t#\x02\t\x01\x0c0x10\x02\x0c\x02*'
    assert _numbers(raw) == [Number(value=0x10, operand=2, standalone=True)]


def test_immediate_decimal() -> None:
    # sub rsp, 8
    raw = '\x01\x05sub\x02\x05 \x01)\x01!rsp\x02!\x02)\x01\t,\x02\t \x01*\x01\x0c8\x02\x0c\x02*'
    assert _numbers(raw) == [Number(value=8, operand=2, standalone=True)]


def test_void_operand() -> None:
    # CMP.W R3, #0x4B000 in libamp.so (ARM, based at 0), where the value falls inside a segment
    raw = (
        '\x01\x05CMP.W\x02\x05           \x01)\x01!R3\x02!\x02)\x01\t,\x02\t \x01*\x01\t#\x02\t\x01\r0x4B000\x02\r\x02*'
    )
    assert _numbers(raw) == [Number(value=0x4B000, operand=2, standalone=True)]


@pytest.mark.parametrize(
    ('raw', 'value'),
    [
        # PowerPC addis r12, r2, -1
        ('\x01+\x01\t-\x02\t\x01\x0c1\x02\x0c\x02+', -1),
        # RISC-V addi t1, t1, -2Ch
        ('\x01+\x01\t-\x02\t\x01\x0c2Ch\x02\x0c\x02+', -0x2C),
        # s390x aghi %r15, -0xA0
        ('\x01*\x01\t-\x02\t\x01\x0c0xA0\x02\x0c\x02*', -0xA0),
    ],
)
def test_sign_is_a_separate_symbol(raw: str, value: int) -> None:
    [number] = _numbers(raw)
    assert number.value == value
    assert number.standalone


def test_dnum_literal_pool() -> None:
    # ARM LDR R1, =0xCBF29CE4
    raw = '\x01*\x01\t=\x02\t\x01\x1f0xCBF29CE4\x02\x1f\x02*'
    assert _numbers(raw) == [Number(value=0xCBF29CE4, operand=2, standalone=True)]


def test_displacement() -> None:
    # lea ecx, [rdi-41h]
    raw = '\x01*\x01\t[\x02\t\x01!rdi\x02!\x01\t-\x02\t\x01\x0c41h\x02\x0c\x01\t]\x02\t\x02*'
    assert _numbers(raw) == [Number(value=-0x41, operand=2, standalone=False)]


def test_sign_merged_into_a_longer_symbol() -> None:
    # ARM64 STP XZR, XZR, [X1,#-0xD8]
    raw = '\x01+\x01\t[\x02\t\x01!X1\x02!\x01\t,#-\x02\t\x01\x0c0xD8\x02\x0c\x01\t]\x02\t\x02+'
    assert _numbers(raw) == [Number(value=-0xD8, operand=3, standalone=False)]


def test_post_index() -> None:
    # ARM64 STRB W19, [X1],#-1
    raw = '\x01*\x01\t[\x02\t\x01!X1\x02!\x01\t],#-\x02\t\x01\x0c1\x02\x0c\x02*'
    assert _numbers(raw) == [Number(value=-1, operand=2, standalone=False)]


def test_frame_size_plus_stack_variable() -> None:
    # mov [rsp+28h+var_20], rbp
    raw = (
        '\x01)\x01\t[\x02\t\x01!rsp\x02!\x01\t+\x02\t\x01\x0c28h\x02\x0c\x01\t+\x02\t'
        '\x01\x19var_20\x02\x19\x01\t]\x02\t\x02)'
    )
    assert _numbers(raw) == [Number(value=0x28, operand=1, standalone=False)]


def test_subtracted_from_a_name() -> None:
    # movsxd rax, ds:(jpt_27842 - 0D11E8h)[rdx+rax*4]
    raw = (
        '\x01*\x01!ds\x02!\x01\t:(\x02\t\x01\x07\x01(00000000000D11E8jpt_27842\x02\x07 \x01\t-\x02\t '
        '\x01\x0c0D11E8h\x02\x0c\x01\t)[\x02\t\x01!rdx\x02!\x01\t+\x02\t\x01!rax\x02!\x01\t*4]\x02\t\x02*'
    )
    assert _numbers(raw) == [Number(value=-0xD11E8, operand=2, standalone=False)]


def test_negated_parenthesis_is_not_the_numbers_sign() -> None:
    # ARM SUB.W R7, R11, #-(0x4DC+var_4E8+3)
    raw = (
        '\x01+\x01\t#-(\x02\t\x01\x0c0x4DC\x02\x0c\x01\t+\x02\t\x01\x19var_4E8\x02\x19'
        '\x01\t+\x02\t\x01\x0c3\x02\x0c\x01\t)\x02\t\x02+'
    )
    assert _numbers(raw) == [
        Number(value=0x4DC, operand=3, standalone=False),
        Number(value=3, operand=3, standalone=False),
    ]


def test_two_numbers_in_one_operand() -> None:
    # PowerPC insrdi r3, r9, 32,0
    raw = '\x01+\x01\x0c32\x02\x0c\x01\t,\x02\t\x01\x0c0\x02\x0c\x02+'
    assert _numbers(raw) == [
        Number(value=32, operand=3, standalone=False),
        Number(value=0, operand=3, standalone=False),
    ]


def test_number_in_a_comment_has_no_operand() -> None:
    # PowerPC ori r3, r9, 0x2325 # 0xFFFFFFFF84222325
    raw = '\x01+\x01\x0c0x2325\x02\x0c\x02+ \x01\x04#\x02\x04 \x01\x0c0xFFFFFFFF84222325\x02\x0c'
    assert _numbers(raw) == [
        Number(value=0x2325, operand=3, standalone=True),
        Number(value=0xFFFFFFFF84222325, operand=None, standalone=False),
    ]


def test_float_is_skipped() -> None:
    # ARM64 FMOV D0, #-20.0
    raw = '\x01*\x01\t#\x02\t\x01\x0c-20.0\x02\x0c\x02*'
    assert _numbers(raw) == []


def test_line_without_numbers() -> None:
    assert _numbers('\x01\x05nop\x02\x05') == []


@pytest.mark.parametrize(
    ('value', 'method', 'expected'),
    [
        (-1, Number.u32, 0xFFFFFFFF),
        (0xFFFFFFFF, Number.i32, -1),
        (0xFFFFFFFF, Number.u32, 0xFFFFFFFF),
        (-1, Number.i32, -1),
        (0x1_0000_0000, Number.u32, None),
        (-0x8000_0001, Number.u32, None),
        (-0x8000_0001, Number.i32, None),
        (-1, Number.u8, 0xFF),
        (0x80, Number.i8, -0x80),
        (0x100, Number.u8, None),
        (-0x10, Number.u16, 0xFFF0),
        (0x8000, Number.i16, -0x8000),
        (-1, Number.u64, 0xFFFFFFFFFFFFFFFF),
        (0xFFFFFFFFFFFFFFFF, Number.i64, -1),
        (0x1_0000_0000_0000_0000, Number.u64, None),
    ],
)
def test_width(value: int, method: object, expected: int | None) -> None:
    assert callable(method)
    assert method(Number(value=value, operand=1, standalone=True)) == expected
