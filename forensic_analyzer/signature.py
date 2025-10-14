# forensic_analyzer/signature.py
from __future__ import annotations
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import io
import os
import mimetypes

# python-magic (libmagic) 사용 시 더 정확한 판정 가능, 없으면 mimetypes(내장 라이브러리) 사용해서 진행
try:
    import magic  # type: ignore
    _HAS_MAGIC = True
except Exception:
    _HAS_MAGIC = False



# 공개 API. 파일 종류 판별할 때 아래 함수 호출.

def probe_file_type(
    path: Union[str, Path],
    *,
    prefer_magic: bool = True
) -> Optional[Dict[str, str]]:
    """
    실제 바이트 내용을 기반으로 파일 타입(=MIME)과 설명을 판정.
    - 성공 시: {"real_mime": "...", "real_ext": ".ext" or "", "description": "..."} 반환
        · real_ext는 MIME에서 추정한 확장자. 없으면 "".
    - 실패(접근 불가/읽기 실패 등) 시: None
    - python-magic(libmagic)가 있으면 그것을 우선 사용, 없으면 mimetypes 폴백
    """
    path = Path(path)

    # 접근/열기 가능한지 간단 체크
    try:
        st = path.stat()
        if not path.is_file():
            return None
    except (OSError, PermissionError):
        return None

    real_mime = ""
    description = ""

    if prefer_magic and _HAS_MAGIC:
        try:
            # mime=True면 official MIME string, False면 인간 친화적 설명
            real_mime = magic.from_file(str(path), mime=True) or ""
            description = magic.from_file(str(path), mime=False) or ""
        except Exception:
            # libmagic 오류가 나면 mimetypes 대신 사용
            real_mime, description = "", ""
    if not real_mime:
        mime_guess, _ = mimetypes.guess_type(str(path))
        real_mime = mime_guess or ""
        description = description or (real_mime if real_mime else "")

    real_ext = _ext_from_mime(real_mime)
    return {
        "real_mime": real_mime,
        "real_ext": real_ext,
        "description": description,
    }


def add_signature_to_rows(
    rows: List[Dict[str, object]],
    *,
    prefer_magic: bool = True,
    disk_ext_field: str = "ext_on_disk",
    sig_prefix: str = "sig_",          # 생성 컬럼 접두어 (예를 들어: sig_mime, sig_ext, sig_desc, ext_mismatch)
    missing_as: str = ""
) -> List[Dict[str, object]]:
    """
    인벤토리 행 리스트에 시그니처 정보를 추가한다.
    - 입력: rows[i]["path"] 가 필수
    - 추가 컬럼:
        {sig_prefix}mime        : 실제 MIME (예: "image/jpeg")
        {sig_prefix}ext         : 시그니처 기반 확장자 (예: ".jpg" 또는 "")
        {sig_prefix}desc        : libmagic 설명(가능 시)
        ext_on_disk             : 디스크상의 확장자 (".jpg" 형태, 없으면 "")
        ext_mismatch            : 불일치 여부(bool) — True면 확장자/시그니처 불일치
    - 읽기 실패 시 missing_as로 채움, mismatch는 False
    """
    for row in rows:
        p = row.get("path")
        if not p:
            row[f"{sig_prefix}mime"] = missing_as
            row[f"{sig_prefix}ext"] = missing_as
            row[f"{sig_prefix}desc"] = missing_as
            row["ext_mismatch"] = False
            row[disk_ext_field] = missing_as
            continue

        result = probe_file_type(p, prefer_magic=prefer_magic)
        disk_ext = _disk_extension(str(p))

        if result is None:
            row[f"{sig_prefix}mime"] = missing_as
            row[f"{sig_prefix}ext"] = missing_as
            row[f"{sig_prefix}desc"] = missing_as
            row["ext_mismatch"] = False
            row[disk_ext_field] = disk_ext or missing_as
        else:
            row[f"{sig_prefix}mime"] = result.get("real_mime", "") or missing_as
            row[f"{sig_prefix}ext"]  = result.get("real_ext", "") or missing_as
            row[f"{sig_prefix}desc"] = result.get("description", "") or missing_as
            row[disk_ext_field] = disk_ext or missing_as
            row["ext_mismatch"] = _is_ext_mismatch(
                disk_ext,
                result.get("real_ext", ""),
                result.get("real_mime", "")
            )
    return rows

# 이하 내부유틸!
# mimetypes가 반환하는 확장자는 환경/플랫폼에 따라 None이거나 다소 특이할 수 있음 주의, 추후 재확인


_KNOWN_EXT_NORMALIZE = {
    ".jpe": ".jpg",
    ".jpeg": ".jpg",
    ".tif": ".tiff",
    ".htm": ".html",
}

def _normalize_ext(ext: str) -> str:
    ext = (ext or "").strip().lower()
    if not ext:
        return ""
    if not ext.startswith("."):
        ext = "." + ext
    return _KNOWN_EXT_NORMALIZE.get(ext, ext)


def _disk_extension(path: str) -> str:
    # 순수 디스크상 확장자 (".txt" 형태). 만약에 없으면 ""
    ext = Path(path).suffix
    return _normalize_ext(ext)


def _ext_from_mime(mime: str) -> str:
    # MIME → 확장자 추정 (없거나 모르면 "")
    if not mime:
        return ""
    guessed = mimetypes.guess_extension(mime) or ""
    return _normalize_ext(guessed)


def _is_ext_mismatch(disk_ext: str, real_ext: str, real_mime: str) -> bool:
    """
    확장자/시그니처 불일치 판정.
    - 둘 다 비어 있으면 False (판정 불가. 다소 보수적으로 일치 처리하는 방향으로.)
    - disk_ext 존재 && real_ext 비어있음 && MIME을 모르는 상황 == False
    - 둘 다 있으면 확장자 정규화해서 비교
    """
    d = _normalize_ext(disk_ext)
    r = _normalize_ext(real_ext)

    if not d and not r:
        return False
    if d and not r:
        # 만약 MIME 모르면? 불일치로 확실하게 단정할수는 없음
        return False
    return d != r
