"""시그니처 판별과 확장자 위장 탐지 테스트. libmagic 유무 두 경로를 모두 검사한다."""
from __future__ import annotations

import os
import random
import zipfile
from pathlib import Path
from typing import Dict, Union

import pytest

from conftest import MAGIC_MODES, can_symlink
from forensic_analyzer.signature import add_signature_to_rows, is_ext_mismatch, probe_file_type

PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
       b"\x00\x00\x00\x0aIDATx\x01\x01\x01\x00\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00IEND\xaeB`\x82")
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _mismatch(path: Path, magic: bool) -> bool:
    row = add_signature_to_rows([{"path": str(path)}], prefer_magic=magic)[0]
    return row["ext_mismatch"]


def _zip_bytes(tmp_path: Path, member: Union[str, Dict[str, bytes]]) -> bytes:
    """ZIP 바이트를 만든다. 문자열이면 그 이름의 파일 하나(내용 ``x``), 딕셔너리면 이름 → 내용."""
    members = {member: b"x"} if isinstance(member, str) else member
    z = tmp_path / "_tmp.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    data = z.read_bytes()
    z.unlink()
    return data


AXML = b"\x03\x00\x08\x00" + bytes(60)          # 컴파일된 AndroidManifest.xml 앞부분
DEX = b"dex\n035\x00" + bytes(100)
APK = {"AndroidManifest.xml": AXML, "classes.dex": DEX, "classes2.dex": DEX, "resources.arsc": b"\x02\x00\x0c\x00"}
XML_PLIST = b'<?xml version="1.0"?>\n<plist version="1.0"><dict/></plist>\n'
IPA = {"Payload/Notes.app/Info.plist": XML_PLIST, "Payload/Notes.app/Notes": b"\xcf\xfa\xed\xfe" + bytes(100)}
DOCX = {"[Content_Types].xml": b"<Types/>", "_rels/.rels": b"<Relationships/>", "word/document.xml": b"<w:document/>"}
XLSX = {"[Content_Types].xml": b"<Types/>", "xl/workbook.xml": b"<workbook/>"}


ELF = b"\x7fELF\x02\x01\x01" + bytes(57) + b"\x00" * 400
TIFF = b"II*\x00\x08\x00\x00\x00" + bytes(500)
CR2 = b"II*\x00\x10\x00\x00\x00CR\x02\x00" + bytes(500)   # 캐논 RAW: TIFF 헤더 + "CR"


def _ftyp(brand: bytes) -> bytes:
    return b"\x00\x00\x00\x18ftyp" + brand + bytes(500)


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
        "elf_as.jpg": ELF,                                         # 사진으로 위장한 리눅스 실행 파일
        "raw_as.png": CR2,
        # ZIP 내부 구조: 확장자가 요구하는 앱·문서 구조가 없음
        "plain_zip.apk": _zip_bytes(tmp_path, "photo.jpg"),                     # 일반 압축 파일 이름만 바꿈
        "docx_as.apk": _zip_bytes(tmp_path, DOCX),                             # 워드 문서 이름만 바꿈
        "text_manifest.apk": _zip_bytes(tmp_path, {"AndroidManifest.xml": b"<manifest/>", "classes.dex": DEX}),
        "fake_dex.apk": _zip_bytes(tmp_path, {**APK, "classes2.dex": b"not a dex file"}),
        "plain_zip.ipa": _zip_bytes(tmp_path, "readme.txt"),
        "fake_plist.ipa": _zip_bytes(tmp_path, {"Payload/X.app/Info.plist": b"just text"}),
        "apk_as.docx": _zip_bytes(tmp_path, APK),                              # 진짜 앱을 문서로 위장
        "docx_as.xlsx": _zip_bytes(tmp_path, DOCX),
        "plain_zip.hwpx": _zip_bytes(tmp_path, "Contents/section0.xml"),        # mimetype 없음
        "truncated.apk": _zip_bytes(tmp_path, APK)[:120],                     # 끝이 잘려 구조를 못 읽음
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
        "app.apk": _zip_bytes(tmp_path, APK),
        "split.apk": _zip_bytes(tmp_path, {"AndroidManifest.xml": AXML, "res/a.xml": AXML}),  # DEX 없는 분할 APK
        "app.ipa": _zip_bytes(tmp_path, IPA),
        "bplist.ipa": _zip_bytes(tmp_path, {"Payload/A.app/Info.plist": b"bplist00" + bytes(40)}),
        "report.docx": _zip_bytes(tmp_path, DOCX), "macro.docm": _zip_bytes(tmp_path, DOCX),
        "sheet.xlsx": _zip_bytes(tmp_path, XLSX),
        "doc.hwpx": _zip_bytes(tmp_path, {"mimetype": b"application/hwp+zip", "Contents/section0.xml": b"<s/>"}),
        "book.epub": _zip_bytes(tmp_path, {"mimetype": b"application/epub+zip", "OEBPS/a.xhtml": b"<p/>"}),
        "apk_as.zip": _zip_bytes(tmp_path, APK),                                # APK도 ZIP인 것은 사실
        "lib.jar": _zip_bytes(tmp_path, "META-INF/MANIFEST.MF"),
        "tool.exe": _pe_bytes(),
        "mz_note.txt": b"MZ is the start of this plain note.\n" * 30,
        "bmw.txt": b"BMW review text\n" * 30,
        "clip.webp": b"RIFF" + (500).to_bytes(4, "little") + b"WEBPVP8 " + bytes(500),
        "photo.heic": b"\x00\x00\x00\x18ftypheic" + bytes(500),
        "mail.eml": b"From: a@b.c\nSubject: hi\n\nbody\n" * 20,
        # 2차 리뷰에서 재현된 오탐: 리눅스 실행 파일·라이브러리
        "ls": ELF, "libc.so.6": ELF, "mod.ko": ELF,
        # 카메라 RAW(TIFF 구조)
        "IMG_0001.CR2": CR2, "DSC_0001.NEF": TIFF, "photo.dng": TIFF,
        # ftyp 계열 세부 형식
        "clip.m4v": _ftyp(b"M4V "), "img.avif": _ftyp(b"avif"), "odd_brand.mp4": _ftyp(b"zzzz"),
        # ZIP·gzip 계열
        "doc.pages": _zip_bytes(tmp_path, "Index/Document.iwa"), "pkg.whl": _zip_bytes(tmp_path, "pkg/__init__.py"),
        "a.tgz": b"\x1f\x8b\x08\x00" + rng.randbytes(600),
        # 중간이 0으로 채워진 로그, 텍스트 키 파일, 모르는 확장자
        "midnul.log": b"[INFO] ok\n" * 300 + b"\x00" * 4096 + b"[INFO] resumed\n" * 300,
        "server.key": b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n",
        "blob.xyz": PNG,
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
    ("", "application/x-executable", "", False),   # 확장자 없는 실행 파일은 정상
    ("", "application/pdf", ".pdf", True),         # 확장자를 떼어 숨긴 PDF
    (".6", "application/x-executable", "", False), # 모르는 확장자는 판정 불가
    (".cr2", "image/x-canon-cr2", "", False),
    (".txt", "application/octet-stream", "", True),
    (".png", "application/octet-stream", "", True),
    (".bin", "application/octet-stream", "", False),
    (".txt", "inode/x-empty", "", False),
    ("", "image/png", ".png", True),
    ("", "text/plain", ".txt", False),
    ("", "application/vnd.sqlite3", ".sqlite", False),
    (".JPEG", "image/jpeg", ".jpg", False),
    (".hwp", "application/x-ole-storage", ".doc", False),
    (".db", "application/CDFV2", "", False),
])
def test_rule_table(disk: str, mime: str, ext: str, expected: bool) -> None:
    assert is_ext_mismatch(disk, mime, ext) is expected


def test_embedded_rule() -> None:
    assert is_ext_mismatch(".txt", "text/plain", ".txt", embedded_binary=True)
    assert not is_ext_mismatch(".txt", "text/plain", ".txt", embedded_binary=False)


@pytest.mark.parametrize("magic", MAGIC_MODES)
def test_zip_container_identified(write, tmp_path: Path, magic: bool) -> None:
    """ZIP은 libmagic 유무와 관계없이 내부 구조로 판별하고 근거를 남긴다."""
    row = add_signature_to_rows([{"path": str(write("x.apk", _zip_bytes(tmp_path, APK)))}], prefer_magic=magic)[0]
    assert row["sig_mime"] == "application/vnd.android.package-archive"
    assert row["sig_source"] == "container"
    assert "DEX 2개" in row["sig_desc"]

    row = add_signature_to_rows([{"path": str(write("y.apk", _zip_bytes(tmp_path, "a.txt")))}], prefer_magic=magic)[0]
    assert row["sig_mime"] == "application/zip"
    assert "일반 ZIP" in row["sig_desc"]




@pytest.mark.parametrize("field,flag", [(8, 0x01), (10, 0x1234)])   # 암호화 플래그 / 지원하지 않는 압축 방식
def test_zip_container_unreadable_core_file(write, tmp_path: Path, field: int, flag: int) -> None:
    """핵심 내부 파일을 읽지 못하면 앱으로 인정하지 않되, "APK 아님"으로 단정하지도 않는다."""
    from forensic_analyzer.container import inspect_zip
    data = bytearray(_zip_bytes(tmp_path, APK))
    cd = data.index(b"PK\x01\x02")        # 첫 중앙 디렉터리 항목 = AndroidManifest.xml
    value = int.from_bytes(data[cd + field:cd + field + 2], "little") | flag
    data[cd + field:cd + field + 2] = value.to_bytes(2, "little")
    found = inspect_zip(write("tampered.apk", bytes(data)))
    assert found.kind == ""
    assert "읽을 수 없음" in found.desc and "APK 아님" not in found.desc


def test_zip_container_duplicate_names(write, tmp_path: Path) -> None:
    """같은 이름의 내부 파일이 여러 개면 어느 것을 판정했는지 보장할 수 없어 인정하지 않는다."""
    import warnings
    from forensic_analyzer.container import inspect_zip
    z = tmp_path / "dup.apk"
    with warnings.catch_warnings(), zipfile.ZipFile(z, "w") as zf:
        warnings.simplefilter("ignore")              # zipfile의 중복 이름 경고
        zf.writestr("AndroidManifest.xml", b"<fake/>")
        zf.writestr("AndroidManifest.xml", AXML)
    found = inspect_zip(z)
    assert found.kind == "" and "변조 의심" in found.desc
    assert add_signature_to_rows([{"path": str(z)}], prefer_magic=False)[0]["ext_mismatch"]


def test_zip_container_generic_desc_keeps_declared_mimetype(write, tmp_path: Path) -> None:
    """확인 대상이 아닌 ZIP 기반 문서(ODG 등)를 "문서가 아니다"로 적지 않는다."""
    from forensic_analyzer.container import inspect_zip
    odg = {"mimetype": b"application/vnd.oasis.opendocument.graphics", "content.xml": b"<c/>"}
    found = inspect_zip(write("draw.odg", _zip_bytes(tmp_path, odg)))
    assert found.kind == "" and "mimetype=application/vnd.oasis.opendocument.graphics" in found.desc
