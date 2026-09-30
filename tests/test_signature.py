"""시그니처 판별과 확장자 위장 탐지 테스트. libmagic 유무 두 경로를 모두 검사한다."""
from __future__ import annotations

import os
import random
import zipfile
from pathlib import Path

import pytest

from conftest import MAGIC_MODES, can_symlink
from forensic_analyzer.signature import add_signature_to_rows, is_ext_mismatch, probe_file_type

PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
       b"\x00\x00\x00\x0aIDATx\x01\x01\x01\x00\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00IEND\xaeB`\x82")
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _mismatch(path: Path, magic: bool) -> bool:
    row = add_signature_to_rows([{"path": str(path)}], prefer_magic=magic)[0]
    return row["ext_mismatch"]


def _zip_bytes(tmp_path: Path, member: str) -> bytes:
    """``member`` 하나를 담은 ZIP 바이트를 만든다(형식별로 실제와 비슷한 내부 파일명 사용)."""
    z = tmp_path / "_tmp.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr(member, "x")
    data = z.read_bytes()
    z.unlink()
    return data


def _pe_bytes() -> bytes:
    """최소 구조의 윈도우 PE(EXE) 헤더."""
    return (b"MZ" + b"\x90" * 58 + (0x80).to_bytes(4, "little") + b"\x00" * (0x80 - 0x40)
            + b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 400)


@pytest.mark.parametrize("magic", MAGIC_MODES)
def test_must_detect(write, tmp_path: Path, rng: random.Random, magic: bool) -> None:
    """잡아야 하는 위장."""
    cases = {
        "png_as.jpg": PNG,
        "random.txt": rng.randbytes(4096),
        "bom_random.txt": b"\xff\xfe" + rng.randbytes(4096),
        "header_wiped.png": rng.randbytes(2000),
        "noext_png": PNG,
        "text_then_payload.txt": ("안건 검토\n" * 3000).encode() + rng.randbytes(12000),
        "exe_as.jpg": _pe_bytes(),                                  # 사진으로 위장한 실행 파일
        "exe_as.txt": _pe_bytes(),
        "docx_as.txt": _zip_bytes(tmp_path, "word/document.xml"),   # 확장자만 바꾼 문서
        "fake.exe": b"not really an executable\n" * 20,
    }
    for name, data in cases.items():
        assert _mismatch(write(name, data), magic), name


@pytest.mark.parametrize("magic", MAGIC_MODES)
def test_must_not_flag(write, tmp_path: Path, rng: random.Random, magic: bool) -> None:
    """정상 파일은 불일치로 잡으면 안 된다."""
    cases = {
        "a.py": b"print('hello')\n" * 20,
        "b.html": b"<html><body>x</body></html>\n" * 20,
        "c.log": b"[2025] INFO start\n" * 100 + b"\x00" * 3000,
        "latin1.txt": ("café naïve " * 300).encode("latin-1"),
        "sjis.txt": ("日本語のテキスト。" * 200).encode("shift_jis"),
        "u16nobom.txt": ("한국어 메모 비밀번호 " * 200).encode("utf-16-le"),
        "u16bom_zh.txt": "".join(chr(0x4E00 + (i * 7919) % 20000) for i in range(3000)).encode("utf-16"),
        "doc.hwp": OLE + rng.randbytes(600),
        "Thumbs.db": OLE + rng.randbytes(1000),
        "app.apk": _zip_bytes(tmp_path, "AndroidManifest.xml"),
        "doc.hwpx": _zip_bytes(tmp_path, "Contents/section0.xml"),
        "tool.exe": _pe_bytes(),
        "mz_note.txt": b"MZ is the start of this plain note.\n" * 30,
        "bmw.txt": b"BMW review text\n" * 30,
        "clip.webp": b"RIFF" + (500).to_bytes(4, "little") + b"WEBPVP8 " + bytes(500),
        "photo.heic": b"\x00\x00\x00\x18ftypheic" + bytes(500),
        "mail.eml": b"From: a@b.c\nSubject: hi\n\nbody\n" * 20,
        "Info.plist": b'<?xml version="1.0"?>\n<plist version="1.0"><dict/></plist>\n' * 10,
        "data.bin": rng.randbytes(4096),
        "empty.txt": b"",
        "README": b"plain readme text\n" * 10,
        "real.png": PNG,
        "big_text.txt": ("정상적인 긴 텍스트 문서입니다.\n" * 3000).encode(),
    }
    for name, data in cases.items():
        assert not _mismatch(write(name, data), magic), name


def test_unreadable_file_is_error_not_empty(write, monkeypatch: pytest.MonkeyPatch) -> None:
    """읽을 수 없는 파일을 '빈 파일'로 기록하면 안 된다(권한만 막아 검사를 피하는 것 방지)."""
    target = write("locked.png", PNG)
    real_open = Path.open

    def fake_open(self, *a, **kw):
        if self == target:
            raise PermissionError("denied")
        return real_open(self, *a, **kw)

    monkeypatch.setattr(Path, "open", fake_open)
    assert probe_file_type(target, prefer_magic=False) is None
    row = add_signature_to_rows([{"path": str(target)}], prefer_magic=False)[0]
    assert row["sig_source"] == "error"
    assert row["sig_mime"] == ""


def test_symlink_not_followed_is_not_judged(tmp_path: Path, write) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("심볼릭 링크를 만들 수 없는 환경")
    write("t.txt", b"hello\n")
    os.symlink("t.txt", tmp_path / "l.png")
    row = add_signature_to_rows([{"path": str(tmp_path / "l.png"), "is_symlink": True}])[0]
    assert row["sig_source"] == "symlink"
    assert row["ext_mismatch"] is False


@pytest.mark.parametrize("disk,mime,ext,expected", [
    (".jpg", "image/png", ".png", True),
    (".txt", "application/octet-stream", "", True),
    (".png", "application/octet-stream", "", True),
    (".bin", "application/octet-stream", "", False),
    (".txt", "inode/x-empty", "", False),
    ("", "image/png", ".png", True),
    ("", "text/plain", ".txt", False),
    (".JPEG", "image/jpeg", ".jpg", False),
    (".hwp", "application/x-ole-storage", ".doc", False),
    (".db", "application/CDFV2", "", False),
])
def test_rule_table(disk: str, mime: str, ext: str, expected: bool) -> None:
    assert is_ext_mismatch(disk, mime, ext) is expected


def test_embedded_rule() -> None:
    assert is_ext_mismatch(".txt", "text/plain", ".txt", embedded_binary=True)
    assert not is_ext_mismatch(".txt", "text/plain", ".txt", embedded_binary=False)
