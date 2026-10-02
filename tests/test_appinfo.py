"""앱 패키지(APK·IPA) 정보 추출 테스트."""
from __future__ import annotations

import plistlib
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import pytest

from forensic_analyzer.appinfo import collect_app_rows
from forensic_analyzer.dummy_test import android_manifest_bytes
from forensic_analyzer.signature import add_signature_to_rows

DEX = b"dex\n035\x00" + bytes(104)
MANIFEST = android_manifest_bytes("org.example.app", 5, "1.0", 23, 33,
                                  ["android.permission.INTERNET", "android.permission.CAMERA"], "Example")
APK = {"AndroidManifest.xml": MANIFEST, "classes.dex": DEX}


def _zip(path: Path, members: Dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def _ipa(path: Path, plist: dict, fmt=plistlib.FMT_XML, extra: Optional[Dict[str, bytes]] = None) -> Path:
    return _zip(path, {"Payload/Demo.app/Info.plist": plistlib.dumps(plist, fmt=fmt), **(extra or {})})


def _apps(paths: List[Path], hash_algorithms: Sequence[str] = (),
          hashes: Optional[Dict[str, str]] = None) -> Dict[str, dict]:
    """시그니처 판별을 거쳐 앱 행을 만들고 파일 이름으로 찾을 수 있게 돌려준다."""
    rows = [{"path": str(p), "rel_path": p.name, **(hashes or {})} for p in paths]
    add_signature_to_rows(rows, prefer_magic=False)
    return {r["rel_path"]: r for r in collect_app_rows(rows, hash_algorithms=hash_algorithms)}


def test_apk_info(tmp_path: Path) -> None:
    pytest.importorskip("androguard")
    app = _apps([_zip(tmp_path / "a.apk", APK)])["a.apk"]
    assert app["status"] == "ok" and app["structure_ok"] is True
    assert (app["package"], app["app_name"], app["version_name"], app["version_code"]) == \
        ("org.example.app", "Example", "1.0", "5")
    assert (app["min_os"], app["target_sdk"]) == ("23", "33")
    assert app["permissions"] == "android.permission.CAMERA;android.permission.INTERNET"   # 정렬
    assert app["signing"] == ""


def test_apk_kept_as_zip_is_listed(tmp_path: Path) -> None:
    """확장자 위장 판정에서는 정상(.zip)이지만, 앱 목록에는 나와야 한다."""
    pytest.importorskip("androguard")
    app = _apps([_zip(tmp_path / "backup.zip", APK)])["backup.zip"]
    assert app["app_type"] == "APK" and app["package"] == "org.example.app"


@pytest.mark.parametrize("field", [6, 8])   # 로컬 헤더의 암호화 플래그 / 압축 방식
def test_tampered_apk_is_still_read(tmp_path: Path, field: int) -> None:
    """분석 방해용 ZIP 조작이 있어도 정보를 뽑고, 구조 확인 실패는 함께 남긴다."""
    pytest.importorskip("androguard")
    data = bytearray(_zip(tmp_path / "src.apk", APK).read_bytes())
    flag = 0x0001 if field == 6 else 0x1234
    for sig, off in ((b"PK\x03\x04", field), (b"PK\x01\x02", field + 2)):   # 중앙 디렉터리는 2바이트 뒤
        i = data.index(sig) + off
        data[i:i + 2] = (int.from_bytes(data[i:i + 2], "little") | flag).to_bytes(2, "little")
    p = tmp_path / "tampered.apk"
    p.write_bytes(bytes(data))
    app = _apps([p])["tampered.apk"]
    assert app["structure_ok"] is False and "읽을 수 없음" in app["structure_desc"]
    assert app["status"] == "ok" and app["package"] == "org.example.app"


@pytest.mark.parametrize("fmt", [plistlib.FMT_XML, plistlib.FMT_BINARY])
def test_ipa_info(tmp_path: Path, fmt) -> None:
    plist = {"CFBundleIdentifier": "org.example.demo", "CFBundleName": "Demo", "CFBundleShortVersionString": "3.0",
             "CFBundleVersion": "300", "MinimumOSVersion": "16.0", "DTPlatformVersion": "17.2",
             "NSLocationWhenInUseUsageDescription": "지도", "NSCameraUsageDescription": "촬영", "UIFoo": 1}
    extra = {"Payload/Demo.app/_CodeSignature/CodeResources": b"x", "Payload/Demo.app/embedded.mobileprovision": b"x"}
    app = _apps([_ipa(tmp_path / "d.ipa", plist, fmt, extra)])["d.ipa"]
    assert app["status"] == "ok" and app["app_type"] == "IPA"
    assert (app["package"], app["app_name"], app["version_name"], app["version_code"]) == \
        ("org.example.demo", "Demo", "3.0", "300")
    assert (app["min_os"], app["target_sdk"]) == ("16.0", "17.2")
    assert app["permissions"] == "NSCameraUsageDescription;NSLocationWhenInUseUsageDescription"
    assert app["signing"] == "code_signature;provisioning_profile"


def test_ipa_broken_plist_is_parse_error(tmp_path: Path) -> None:
    """앞부분만 plist처럼 보이고 내용이 깨진 Info.plist는 오류로 남긴다."""
    p = _zip(tmp_path / "bad.ipa", {"Payload/X.app/Info.plist": b"<?xml version='1.0'?><plist><dict><key>"})
    app = _apps([p])["bad.ipa"]
    assert app["structure_ok"] is True and app["status"] == "parse_error" and app["detail"]


def test_candidates(tmp_path: Path, write) -> None:
    """앱 확장자인데 앱 표식이 없으면 not_app으로 남기고, 앱과 무관한 파일은 넣지 않는다."""
    paths = [_zip(tmp_path / "renamed.apk", {"photo.jpg": b"\xff\xd8\xff"}),
             write("text.ipa", b"not an app at all\n" * 10),
             _zip(tmp_path / "archive.zip", {"a.txt": b"x"}),
             write("note.txt", b"hello\n" * 10)]
    apps = _apps(paths)
    assert sorted(apps) == ["renamed.apk", "text.ipa"]
    assert {a["status"] for a in apps.values()} == {"not_app"} and apps["text.ipa"]["app_type"] == "IPA"


def test_unreadable_app_file_is_not_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """읽을 수 없는 .apk도 결과에서 빠지면 안 된다(권한만 막아 목록에서 숨기는 것 방지)."""
    target = _zip(tmp_path / "locked.apk", APK)
    real_open = Path.open

    def fake_open(self, *a, **kw):
        if self == target:
            raise PermissionError("denied")
        return real_open(self, *a, **kw)

    monkeypatch.setattr(Path, "open", fake_open)
    app = _apps([target])["locked.apk"]
    assert (app["app_type"], app["status"], app["detail"]) == ("APK", "parse_error", "파일을 읽을 수 없음")


def test_androguard_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """androguard가 없어도 멈추지 않고 이유를 남긴다."""
    monkeypatch.setitem(sys.modules, "androguard.core.apk", None)   # import 시 ImportError
    app = _apps([_zip(tmp_path / "a.apk", APK)])["a.apk"]
    assert app["status"] == "androguard_missing" and app["package"] == ""


def test_hash_columns_are_carried(tmp_path: Path) -> None:
    p = _ipa(tmp_path / "d.ipa", {"CFBundleIdentifier": "x"})
    app = _apps([p], hash_algorithms=["sha512"], hashes={"sha512": "abc"})["d.ipa"]
    assert app["sha512"] == "abc"
