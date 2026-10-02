# forensic_analyzer/appinfo.py
"""앱 패키지(APK·IPA)에서 식별 정보와 권한을 뽑는다.

증거 폴더 안의 앱을 확장자와 상관없이 찾아, 무슨 앱인지(패키지명·번들 ID, 버전)와
무엇을 요구하는지(권한)를 한 줄씩 기록한다. ``.zip``으로 둔 APK도 찾는다.

대상(후보):
    - 시그니처 판별에서 내부 구조가 APK·IPA로 확인된 파일
    - 확인되지 않았지만 확장자가 ``.apk``·``.ipa``이거나, ZIP 안에 앱 표식
      (``AndroidManifest.xml``, ``Payload/<앱>.app/Info.plist``)이 있는 파일.
      암호화 플래그·지원하지 않는 압축 방식처럼 분석을 방해하는 조작이 있어도 정보를
      뽑을 수 있으면 뽑고, ``structure_ok=False``로 구조 확인 실패를 함께 남긴다.

읽는 방법:
    - APK: 매니페스트가 컴파일된 바이너리 XML이라 직접 해석하지 않고 오픈소스
      androguard를 쓴다. androguard는 안드로이드처럼 ZIP 조작을 견디며 읽는다.
    - IPA: ``Info.plist``를 표준 라이브러리 ``plistlib``로 읽는다(XML·바이너리 모두).
      iOS 권한은 ``NS...UsageDescription`` 키(사용자에게 보여 줄 권한 사유)로 나타난다.

Example:
    >>> rows = collect_app_rows([{"path": "ForensicTestData/apps/sample.ipa", "sig_mime": "application/x-ios-app"}])
    >>> rows[0]["package"], rows[0]["permissions"]
    ('org.example.photos', 'NSCameraUsageDescription;NSPhotoLibraryUsageDescription')
"""
from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

from . import container

APP_FIELDS: Tuple[str, ...] = (
    "path", "rel_path", "ext_on_disk", "app_type", "structure_ok", "structure_desc",
    "package", "app_name", "version_name", "version_code", "min_os", "target_sdk",
    "permissions", "signing", "status", "detail",
)

STATUS_OK = "ok"
STATUS_PARSE_ERROR = "parse_error"            # 앱 표식은 있으나 정보를 읽지 못함
STATUS_NOT_APP = "not_app"                    # 앱 확장자이지만 앱 표식이 없음
STATUS_ANDROGUARD_MISSING = "androguard_missing"

APP_EXTS = {".apk": "apk", ".ipa": "ipa"}
_APP_MIMES = {container.CONTAINER_TYPES[k].mime: k for k in ("apk", "ipa")}

# Info.plist는 보통 수 KB다. 크기를 속인 ZIP 항목으로 메모리를 채우지 않도록 상한을 둔다.
MAX_PLIST_BYTES = 4 * 1024 * 1024


def collect_app_rows(
    rows: List[Dict[str, object]], *, hash_algorithms: Sequence[str] = (),
) -> List[Dict[str, object]]:
    """시그니처 판별을 마친 인벤토리 행에서 앱 후보를 골라 정보를 뽑는다.

    Args:
        rows: ``add_signature_to_rows``까지 거친 인벤토리 행. ``path``, ``sig_mime``,
            ``sig_desc``, ``ext_on_disk``를 사용한다.
        hash_algorithms: 인벤토리에서 계산한 해시 알고리즘. 그 열을 결과로 옮긴다
            (앱 해시로 악성 앱 정보를 조회할 수 있게).

    Returns:
        앱 후보마다 한 행. 열은 ``APP_FIELDS``와 해시 열이다.
    """
    out: List[Dict[str, object]] = []
    for row in rows:
        kind, confirmed = _candidate_kind(row)
        if not kind:
            continue
        app = {f: "" for f in APP_FIELDS}
        app.update({k: row.get(k, "") for k in ("path", "rel_path", "ext_on_disk", *hash_algorithms)})
        app["app_type"] = (kind if kind in ("apk", "ipa") else APP_EXTS[str(row.get("ext_on_disk"))]).upper()
        app["structure_ok"] = confirmed
        app["structure_desc"] = row.get("sig_desc", "")
        path = str(row["path"])
        if kind == "apk":
            app.update(extract_apk_info(path))
        elif kind == "ipa":
            app.update(extract_ipa_info(path))
        elif kind == "unreadable":
            app.update(status=STATUS_PARSE_ERROR, detail="파일을 읽을 수 없음")
        else:
            app.update(status=STATUS_NOT_APP, detail="앱 확장자이지만 ZIP 안에 앱 표식이 없음")
        out.append(app)
    return out


def extract_apk_info(path: Union[str, Path]) -> Dict[str, object]:
    """APK에서 패키지명·버전·SDK·권한·서명 방식을 읽는다(androguard 사용).

    Args:
        path: APK 경로.

    Returns:
        ``APP_FIELDS`` 중 앱 정보 열과 ``status``·``detail``.
    """
    try:
        from loguru import logger
        logger.disable("androguard")  # androguard는 분석 과정을 화면에 많이 출력한다.
        from androguard.core.apk import APK
    except ImportError:
        return {"status": STATUS_ANDROGUARD_MISSING, "detail": "APK 정보를 읽으려면 pip install androguard"}

    try:
        apk = APK(str(path))
    except Exception as e:  # 증거 파일은 손상·조작됐을 수 있어 여러 예외가 난다.
        return {"status": STATUS_PARSE_ERROR, "detail": f"{type(e).__name__}: {e}"}
    if not apk.is_valid_APK():
        return {"status": STATUS_PARSE_ERROR, "detail": "AndroidManifest.xml을 해석할 수 없음"}

    info: Dict[str, object] = {
        "package": apk.get_package() or "",
        "app_name": _safe(apk.get_app_name),
        "version_name": apk.get_androidversion_name() or "",
        "version_code": apk.get_androidversion_code() or "",
        "min_os": apk.get_min_sdk_version() or "",
        "target_sdk": apk.get_target_sdk_version() or "",
        "permissions": ";".join(sorted(set(apk.get_permissions()))),
        "signing": ";".join(v for v, ok in (("v1", apk.is_signed_v1), ("v2", apk.is_signed_v2),
                                            ("v3", apk.is_signed_v3)) if _safe(ok)),
        "status": STATUS_OK,
        "detail": "",
    }
    return info


def extract_ipa_info(path: Union[str, Path]) -> Dict[str, object]:
    """IPA의 ``Info.plist``에서 번들 ID·버전·최소 iOS·권한 사유 키와 서명 파일 유무를 읽는다.

    Args:
        path: IPA 경로.

    Returns:
        ``APP_FIELDS`` 중 앱 정보 열과 ``status``·``detail``.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            plist_name = sorted(n for n in names if container.IPA_PLIST.fullmatch(n))[0]
            with zf.open(plist_name) as f:
                raw = f.read(MAX_PLIST_BYTES + 1)
            if len(raw) > MAX_PLIST_BYTES:
                return {"status": STATUS_PARSE_ERROR, "detail": f"{plist_name}이 너무 큼(4MB 초과)"}
            plist = plistlib.loads(raw)
    except Exception as e:
        return {"status": STATUS_PARSE_ERROR, "detail": f"{type(e).__name__}: {e}"}
    if not isinstance(plist, dict):
        return {"status": STATUS_PARSE_ERROR, "detail": f"{plist_name}의 최상위가 사전이 아님"}

    app_dir = plist_name.rsplit("/", 1)[0] + "/"
    signing = [label for label, member in (("code_signature", "_CodeSignature/CodeResources"),
                                           ("provisioning_profile", "embedded.mobileprovision"))
               if app_dir + member in names]
    return {
        "package": _text(plist.get("CFBundleIdentifier")),
        "app_name": _text(plist.get("CFBundleDisplayName") or plist.get("CFBundleName")),
        "version_name": _text(plist.get("CFBundleShortVersionString")),
        "version_code": _text(plist.get("CFBundleVersion")),
        "min_os": _text(plist.get("MinimumOSVersion")),
        "target_sdk": _text(plist.get("DTPlatformVersion")),
        "permissions": ";".join(sorted(k for k in plist if str(k).endswith("UsageDescription"))),
        "signing": ";".join(signing),
        "status": STATUS_OK,
        "detail": "",
    }


def _candidate_kind(row: Dict[str, object]) -> Tuple[str, bool]:
    """인벤토리 행이 앱 후보인지 판단한다.

    Args:
        row: 시그니처 열이 있는 인벤토리 행.

    Returns:
        ``(종류, 구조 확인 여부)``. 종류는 ``apk``/``ipa``, 앱 확장자인데 파일을 읽지
        못했으면 ``unreadable``, 읽었지만 앱 표식이 없으면 ``not_app``, 후보가 아니면 빈 문자열.
        앱 확장자인 파일은 어떤 경우에도 결과에 남긴다(조용히 빼지 않는다).
    """
    app_ext = row.get("ext_on_disk") in APP_EXTS
    if row.get("sig_source") == "error":
        return ("unreadable" if app_ext else ""), False
    mime = str(row.get("sig_mime") or "")
    if mime in _APP_MIMES:
        return _APP_MIMES[mime], True
    if mime == "application/zip":
        hint = _app_marker(str(row["path"]))
        if hint:
            return hint, False
    return ("not_app" if app_ext else ""), False


def _app_marker(path: str) -> str:
    """ZIP 내부 파일 목록에 앱 표식이 있는지 본다(내용은 읽지 않는다).

    Args:
        path: ZIP 경로.

    Returns:
        ``apk``/``ipa`` 또는 빈 문자열.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except Exception:
        return ""
    if "AndroidManifest.xml" in names:
        return "apk"
    if any(container.IPA_PLIST.fullmatch(n) for n in names):
        return "ipa"
    return ""


def _safe(func) -> object:
    """androguard 조회 함수를 호출하고, 실패하면 빈 문자열을 돌려준다.

    앱 이름처럼 resources.arsc까지 해석해야 하는 값은 조작된 APK에서 실패할 수 있는데,
    그 때문에 나머지 정보까지 잃지 않기 위함이다.

    Args:
        func: 인자 없는 조회 함수.

    Returns:
        함수 결과 또는 빈 문자열.
    """
    try:
        return func()
    except Exception:
        return ""


def _text(value: Optional[object]) -> str:
    """plist 값을 CSV에 넣을 문자열로 바꾼다.

    Args:
        value: plist 값.

    Returns:
        문자열. 없으면 빈 문자열.
    """
    return "" if value is None else str(value)
