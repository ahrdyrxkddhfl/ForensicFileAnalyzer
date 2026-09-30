"""텍스트 판별(textutil) 테스트: 정상 텍스트는 모두 텍스트로, 무작위 바이트는 텍스트가 아니게."""
from __future__ import annotations

import random

import pytest

from forensic_analyzer import textutil as T

TEXT_CASES = {
    "ascii": b"hello world\n" * 50,
    "utf8_ko": ("비밀번호 변경 요청 " * 50).encode("utf-8"),
    "cp949": ("비밀번호 변경 요청 " * 50).encode("cp949"),
    "shift_jis": ("日本語のテキストファイルです。" * 50).encode("shift_jis"),
    "gbk": ("这是一个中文文本文件，用于测试。" * 50).encode("gbk"),
    "latin1": ("café naïve résumé " * 50).encode("latin-1"),
    "cp1252_quotes": ("He said “hello” – ok " * 50).encode("cp1252"),
    "utf16le_ko_nobom": ("한국어 메모 비밀번호 " * 50).encode("utf-16-le"),
    "utf16be_ko_nobom": ("한국어 메모 비밀번호\n" * 50).encode("utf-16-be"),
    "utf16le_zh_no_ascii": ("这是一个中文文本文件" * 80).encode("utf-16-le"),
    "utf16be_zh_no_ascii": ("这是一个中文文本文件" * 80).encode("utf-16-be"),
    "utf16_bom_many_hangul": "".join(chr(0xAC00 + (i * 7919) % 11172) for i in range(3000)).encode("utf-16"),
    "utf16_bom_many_hanzi": "".join(chr(0x4E00 + (i * 7919) % 20000) for i in range(3000)).encode("utf-16"),
    "utf16_bom_registry": ('Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER]\r\n"a"="값"\r\n' * 20).encode("utf-16"),
    "utf32_bom": ("테스트 " * 100).encode("utf-32"),
    "nul_padded_log": b"[2025] INFO start\n" * 100 + b"\x00" * 3000,
    "ansi_color_log": b"line\x1b[31mred\x1b[0m\n" * 100,
}


@pytest.mark.parametrize("name", sorted(TEXT_CASES))
def test_real_text_is_detected(name: str) -> None:
    assert T.detect_text_encoding(TEXT_CASES[name]) is not None


def test_ascii_is_not_mistaken_for_utf16() -> None:
    assert T.detect_text_encoding(b"hello world\n" * 50) == "utf-8"
    # UTF-16 판별을 직접 호출해도 ASCII 소문자 문장을 한자로 오인하면 안 된다.
    for text in (b"plain ascii text", b"lowercase words only " * 40, b"thequickbrownfox" * 64):
        assert T.detect_utf16_without_bom(text) is None


@pytest.mark.parametrize("data", [b"", b"\x00" * 100])
def test_empty_or_nul_only_is_not_text(data: bytes) -> None:
    assert T.detect_text_encoding(data) is None


def test_structured_binary_is_not_text() -> None:
    import struct
    data = b"".join(struct.pack("<IHHd", i, i % 7, i % 300, i * 0.5) for i in range(500))
    assert T.detect_text_encoding(data) is None


@pytest.mark.parametrize("size", [100, 300, 1000, 8192])
def test_random_bytes_are_not_text(rng: random.Random, size: int) -> None:
    """RELIABLE_TEXT_MIN_BYTES 이상 크기에서 무작위 바이트가 텍스트로 오판되지 않아야 한다."""
    misses = sum(T.detect_text_encoding(rng.randbytes(size)) is not None for _ in range(300))
    assert misses <= 1


@pytest.mark.parametrize("size", [300, 1000, 8192])
def test_bom_prefix_does_not_bypass(rng: random.Random, size: int) -> None:
    """무작위 바이트 앞에 BOM만 붙여 텍스트 판정을 피할 수 없어야 한다."""
    for bom in (b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf"):
        misses = sum(T.detect_text_encoding(bom + rng.randbytes(size)) is not None for _ in range(100))
        assert misses == 0


@pytest.mark.parametrize("enc", ["utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("text", ["한국어메모비밀번호", "这是一个中文文本文件", "한국어 메모\n", "ひらがなカタカナ"])
def test_utf16_byte_order_is_correct(enc: str, text: str) -> None:
    """바이트 순서를 반대로 읽어도 한자처럼 보이는 경우가 있어, 올바른 순서를 골라야 한다."""
    assert T.detect_utf16_without_bom((text * 40).encode(enc)) == enc


def test_partial_window_is_detected() -> None:
    data = ("비밀번호 변경 요청 " * 500).encode("utf-8")
    assert T.detect_text_encoding(data[1001:9193], partial=True) is not None


def test_entropy_bounds(rng: random.Random) -> None:
    assert T.shannon_entropy(b"aaaa") == 0.0
    assert T.is_high_entropy(rng.randbytes(4096))
    assert not T.is_high_entropy(b"hello world\n" * 400)
    assert not T.is_high_entropy(rng.randbytes(100))  # 표본이 작으면 판단하지 않음
