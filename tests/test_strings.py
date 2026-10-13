import pytest

from ida_colors.color_parser import parse_full
from ida_colors.strings import String, strings


def _strings(raw: str) -> list[String]:
    return strings(parse_full(raw))


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [
        # x86-64 `lea rsi, aSslSession ; "SSL-Session:\n"`
        (
            (
                '\x01\x05lea\x02\x05     \x01)\x01!rsi\x02!\x02)\x01\t,\x02\t \x01*\x01\x06'
                '\x01(00000000000CE237aSslSession\x02\x06\x02*\x01\x04; \x01(00000000000CE237"SSL-Session:\\n"\x02\x04'
            ),
            String(text='SSL-Session:\\n', char=False, addr=0xCE237, truncated=False),
        ),
        # PowerPC `addi r4, r4, (aToManyKeyshare+0x20 - 0x11B4D8) # "%s' (max = %d)"`
        (
            (
                '\x01+\x01\t(\x02\t\x01\x06\x01(000000000011B4F8aToManyKeyshare\x02\x06\x01\t+\x02\t\x01\x0c0x20'
                '\x02\x0c '
                '\x01\t-\x02\t \x01\x0c0x11B4D8\x02\x0c\x01\t)\x02\t\x02+\x01\x04# '
                '\x01(000000000011B518"%s\' (max = %d)"\x02\x04'
            ),
            String(text="%s' (max = %d)", char=False, addr=0x11B518, truncated=False),
        ),
        # MIPS `ld $v0, (off_1337D0 - 0x13B790)($v1) # "../ssl/ssl_cert.c"`
        (
            (
                '\x01*\x01\t(\x02\t\x01\x06\x01(00000000001337D0off_1337D0\x02\x06 \x01\t-\x02\t \x01\x0c0x13B790'
                '\x02\x0c'
                '\x01\t)(\x02\t\x01!$v1\x02!\x01\t)\x02\t\x02*\x01\x04 # \x01(0000000000100000"../ssl/ssl_cert.c"'
                '\x02\x04'
            ),
            String(text='../ssl/ssl_cert.c', char=False, addr=0x100000, truncated=False),
        ),
        # ARM64 `ADRL X0, aNotSupportedFo ; "\" not supported for cpu option \""`
        (
            (
                '\x01*\x01\x06\x01(000000010009EF8BaNotSupportedFo\x02\x06\x02*'
                '\x01\x04; \x01(000000010009EF8B"\\" not supported for cpu option \\""\x02\x04'
            ),
            String(text='\\" not supported for cpu option \\"', char=False, addr=0x10009EF8B, truncated=False),
        ),
        # ARM64 `ADRL X3, aMathNotesDisab ; "Math Notes disabled…"`
        (
            (
                '\x01*\x01\x06\x01(000000010012C490aMathNotesDisab\x02\x06\x02*'
                '\x01\x04; \x01(000000010012C490"Math Notes disabled…"\x02\x04'
            ),
            String(text='Math Notes disabled…', char=False, addr=0x10012C490, truncated=False),
        ),
        # x86-64 `lea rdx, asc_19EEB8 ; "..."`: the string is three dots, not a truncation
        (
            '\x01*\x01\x06\x01(000000000019EEB8asc_19EEB8\x02\x06\x02*\x01\x04; \x01(000000000019EEB8"..."\x02\x04',
            String(text='...', char=False, addr=0x19EEB8, truncated=False),
        ),
    ],
)
def test_string(raw: str, expected: String) -> None:
    assert _strings(raw) == [expected]


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [
        # ARM64 `ADRL X1, aAbiNewnameTagT ; "abi.NewName: tag too long: hw.optional."...`
        (
            (
                '\x01*\x01\x06\x01(000000010009DC0DaAbiNewnameTagT\x02\x06\x02*'
                '\x01\x04; \x01(000000010009DC0D"abi.NewName: tag too long: hw.optional."...\x02\x04'
            ),
            String(text='abi.NewName: tag too long: hw.optional.', char=False, addr=0x10009DC0D, truncated=True),
        ),
        # x86-64 `lea rcx, asc_18A625`, a binary blob with U+FFFD for bytes that aren't UTF-8 and \xNN escapes
        (
            (
                '\x01*\x01\x06\x01(000000000018A625asc_18A625\x02\x06\x02*\x01\x04; '
                '\x01(000000000018A625"�xy���0WX���\\x1C��\\x0FKL��./?\\\\]_\u210d�����"...\x02\x04'
            ),
            String(text='�xy���0WX���\\x1C��\\x0FKL��./?\\\\]_\u210d�����', char=False, addr=0x18A625, truncated=True),
        ),
        # MIPS `daddiu $s7, (aEcdheEcdsaAes1_0 - 0x100000) # "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECD"...`
        (
            (
                '\x01*\x01\t(\x02\t\x01\x06\x01(00000000001003A8aEcdheEcdsaAes1_0\x02\x06 \x01\t-\x02\t '
                '\x01\x0c0x100000\x02\x0c\x01\t)\x02\t\x02*'
                '\x01\x04 # \x01(00000000001003A8"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECD"...\x02\x04'
            ),
            String(text='ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECD', char=False, addr=0x1003A8, truncated=True),
        ),
    ],
)
def test_truncated_string(raw: str, expected: String) -> None:
    assert _strings(raw) == [expected]


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [
        # ARM64 `LDR X0, [X27,#_runtime.urandom_dev@PAGEOFF] ; "/dev/urandom" ...`
        (
            (
                '\x01*\x01\t[\x02\t\x01!X27\x02!\x01\t,#\x02\t\x01\x07\x01(0000000100161DC0_runtime.urandom_dev\x02\x07'
                '\x01 @PAGEOFF\x02 \x01\t]\x02\t\x02*\x01\x04; \x01(000000010015C3F8"/dev/urandom" ...\x02\x04'
            ),
            String(text='/dev/urandom', char=False, addr=0x10015C3F8, truncated=False),
        ),
        # RISC-V `addi a2, a2, %pcrel_lo(loc_8001C) # "tls_any_set_crypto_state" ...`
        (
            (
                '\x01+\x01 %pcrel_lo(\x01\x1a\x01(000000000008001Cloc_8001C\x02\x1a)\x02 \x02+'
                '\x01\x04# \x01(00000000000ADA28"tls_any_set_crypto_state" ...\x02\x04'
            ),
            String(text='tls_any_set_crypto_state', char=False, addr=0xADA28, truncated=False),
        ),
    ],
)
def test_string_through_a_pointer(raw: str, expected: String) -> None:
    # The address is the string's, not the pointer's.
    assert _strings(raw) == [expected]


@pytest.mark.parametrize(
    ('raw', 'chars'),
    [
        # x86-64 `sub esi, 35h ; '5'`, next to a REGCMT
        ("\x01*\x01\x0c35h\x02\x0c\x02* \x01\x04; '5'\x02\x04\x01\x02; switch 27 cases\x02\x02", ['5']),
        # RISC-V `li a5, 3Bh # ';'`, next to a REGCMT
        (
            "\x01*\x01\x0c3Bh\x02\x0c\x02* \x01\x04# ';'\x02\x04\x01\x02# jumptable 0000000000027A7C case 127\x02\x02",
            [';'],
        ),
        # ARM `CMP R4, #0x22 ; '"'`
        ("\x01*\x01\t#\x02\t\x01\x0c0x22\x02\x0c\x02* \x01\x04; '\"'\x02\x04", ['"']),
        # ARM64 `MOV X1, #0x27 ; '''` is an apostrophe, not escaped
        ("\x01*\x01\t#\x02\t\x01\x0c0x27\x02\x0c\x02* \x01\x04; '''\x02\x04", ["'"]),
        # ARM64 `CMP W3, #0x5C ; '\'` is a backslash, not escaped
        ("\x01*\x01\t#\x02\t\x01\x0c0x5C\x02\x0c\x02* \x01\x04; '\\'\x02\x04", ['\\']),
        # s390x `risbg %r4, %r4, 0x3E, 0xBF, 0x3A # '>' ':'`
        (
            (
                '\x01+\x01\x0c0x3E\x02\x0c\x02+\x01\t,\x02\t \x01,\x01\x0c0xBF\x02\x0c\x02,\x01\t,\x02\t \x01-'
                '\x01\x0c0x3A\x02\x0c'
                "\x02- \x01\x04# '>' ':'\x02\x04"
            ),
            ['>', ':'],
        ),
        # s390x `rosbg %r1, %r2, 0x22, 0x27, 0x18 # '"' '''`
        (
            (
                '\x01+\x01\x0c0x22\x02\x0c\x02+\x01\t,\x02\t \x01,\x01\x0c0x27\x02\x0c\x02,\x01\t,\x02\t \x01-'
                '\x01\x0c0x18'
                "\x02\x0c\x02- \x01\x04# '\"' '''\x02\x04"
            ),
            ['"', "'"],
        ),
        # MIPS `li $a1, 0x3A  # ':' # c`, with a space before the `#`, next to a REGCMT
        ("\x01*\x01\x0c0x3A\x02\x0c\x02* \x01\x04 # ':'\x02\x04\x01\x02 # c\x02\x02", [':']),
        # PowerPC `ori r4, r4, 0x20 # ' ' # 0x80020`: the second AUTOCMT holds only `#`, the number is outside it
        (
            "\x01+\x01\x0c0x20\x02\x0c\x02+ \x01\x04# ' '\x02\x04 \x01\x04#\x02\x04 \x01\x0c0x80020\x02\x0c",
            [' '],
        ),
    ],
)
def test_char(raw: str, chars: list[str]) -> None:
    assert _strings(raw) == [String(text=c, char=True, addr=None, truncated=False) for c in chars]


@pytest.mark.parametrize(
    'raw',
    [
        # PowerPC `ld r0, (__gmon_start___ptr - 0x167D00)(r2) # __gmon_start__`: a name, shaped like a string
        (
            '\x01*\x01\t(\x02\t\x01\x06\x01(000000000015FD08__gmon_start___ptr\x02\x06 \x01\t-\x02\t '
            '\x01\x0c0x167D00\x02\x0c\x01\t)(\x02\t\x01!r2\x02!\x01\t)\x02\t\x02*'
            '\x01\x04# \x01(0000000000164A90__gmon_start__\x02\x04'
        ),
        # x86-64 `call _ZN4core9panicking5panic17h97167cd315d19cd4E ; core::panicking::panic::h97167cd315d19cd4`
        (
            '\x01\x05call\x02\x05    \x01)\x01\x18\x01(00000000000688D0_ZN4core9panicking5panic17h97167cd315d19cd4E'
            '\x02\x18'
            '\x02)\x01\x04; \x01(00000000000688D0core::panicking::panic::h97167cd315d19cd4\x02\x04'
        ),
        # ARM64 `; off_1001632A0 ...`, a name through a pointer
        '\x01\x04; \x01(00000001001632A0off_1001632A0 ...\x02\x04',
        # ARM `MOV R12, #1 ; Alternative name is '__eqdf2'`: a REGCMT, not an AUTOCMT
        "\x01*\x01\t#\x02\t\x01\x0c1\x02\x0c\x02*\x01\x02; Alternative name is '__eqdf2'\x02\x02",
        # ARM `ADD R2, PC, R2 ; sub_18234 ; start_routine`: an AUTOCMT nested in a REGCMT, with no prefix of its own
        '\x01+\x01!R2\x02!\x02+\x01\x02; \x01\x04\x01(0000000000018234sub_18234 \x02\x04; start_routine\x02\x02',
        # RISC-V `# extrn __imp_OPENSSL_sk_dup`: IMPNAME's tag byte is `"`
        '\x01\x04# extrn \x01(00000000000E27B8\x01"\x01(00000000000E27B8__imp_OPENSSL_sk_dup\x02"\x02\x04',
        # x86-64 `call rax ; __gmon_start__`: the name is outside the AUTOCMT
        '\x01)\x01!rax\x02!\x02)\x01\x04 ; \x02\x04\x01"\x01(000000000010EAA8__gmon_start__\x02"',
        # PowerPC `ori r3, r9, 0x2325 # 0xFFFFFFFF84222325`: a number comment
        '\x01+\x01\x0c0x2325\x02\x0c\x02+ \x01\x04#\x02\x04 \x01\x0c0xFFFFFFFF84222325\x02\x0c',
        # A quote that doesn't close
        '\x01\x04; \x01(00000000000CE237"SSL-Session:\x02\x04',
        # An escape that runs into the closing quote
        '\x01\x04; \x01(00000000000CE237"SSL-Session:\\"\x02\x04',
        # Something other than the known suffixes after the string
        '\x01\x04; \x01(00000000000CE237"SSL-Session:" weak\x02\x04',
        # A char without the comment prefix, and a two-char constant
        "\x01\x04'5'\x02\x04",
        "\x01\x04; 'AB'\x02\x04",
    ],
)
def test_not_a_string(raw: str) -> None:
    assert _strings(raw) == []


def test_order_of_appearance() -> None:
    # Made up: a char, a string in an AUTOCMT nested in a REGCMT, then a truncated string.
    raw = (
        '\x01\x04; \'A\'\x02\x04\x01\x02; \x01\x04; \x01(0000000000001000"first"\x02\x04\x02\x02'
        '\x01\x04; \x01(0000000000002000"second"...\x02\x04'
    )
    assert _strings(raw) == [
        String(text='A', char=True, addr=None, truncated=False),
        String(text='first', char=False, addr=0x1000, truncated=False),
        String(text='second', char=False, addr=0x2000, truncated=True),
    ]


def test_line_without_strings() -> None:
    assert _strings('\x01\x05nop\x02\x05') == []
