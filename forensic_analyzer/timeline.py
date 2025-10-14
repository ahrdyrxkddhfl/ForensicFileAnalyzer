# forensic_analyzer/timeline.py
from __future__ import annotations
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union


#api


@dataclass(frozen=True)
class EventSpec:
    field: str       # inventory 열 이름 (예: "mtime_epoch")
    label: str       # 타임라인 이벤트 라벨 (예: "Modified")


DEFAULT_EVENTS: Tuple[EventSpec, ...] = (
    EventSpec("birthtime_epoch", "Created"),          # macOS/일부 FS만 제공 (Windows는 ctime==create)
    EventSpec("ctime_epoch",      "MetadataChanged"), # Windows에선 사실상 Created 역할, POSIX에선 i-node metadata
    EventSpec("mtime_epoch",      "Modified"),
    EventSpec("atime_epoch",      "Accessed"),
)


def build_timeline_rows(
    rows: List[Dict[str, Union[str, int, float, bool, None]]],
    *,
    events: Tuple[EventSpec, ...] = DEFAULT_EVENTS,
    tz_offset_minutes: Optional[int] = None,
    drop_na: bool = True,
    emit_inventory_fields: Tuple[str, ...] = ("path", "name", "parent", "size_bytes", "is_symlink"),
    iso_with_tz: bool = True,
) -> List[Dict[str, Union[str, int, float, bool]]]:
    """
    인벤토리 rows(list[dict])를 '타임라인 이벤트 행'으로 펼쳐서 정렬해 반환.
    - 파일 1개 → 이벤트(생성/수정/접근 등)별로 최대 4행 생성
    - 각 행 컬럼:
        ts_epoch: float   (UTC epoch)
        ts_iso:   str     (ISO 8601 문자열, 로컬/지정 오프셋 반영)
        event:    str     ("Created" / "MetadataChanged" / "Modified" / "Accessed")
        + emit_inventory_fields에서 고른 원본 필드들
    - tz_offset_minutes:
        · None → 시스템 로컬 타임존
        · 0    → UTC
        · 정수 → 해당 오프셋(분) 적용 (예: KST=+540)
    - drop_na: 타임스탬프가 None/0/음수 등 유효하지 않으면 행을 생성하지 않음
    """
    tzinfo = _resolve_tzinfo(tz_offset_minutes)
    out: List[Dict[str, Union[str, int, float, bool]]] = []

    for row in rows:
        base = {k: row.get(k) for k in emit_inventory_fields}
        for spec in events:
            val = row.get(spec.field)  # epoch float 기대
            epoch = _to_epoch_float(val)

            if epoch is None:
                if drop_na:
                    continue
                else:
                    epoch = 0.0

            ts_iso = _epoch_to_iso(epoch, tzinfo=tzinfo, with_tz=iso_with_tz)
            out.append({
                **base,
                "event": spec.label,
                "ts_epoch": float(epoch),
                "ts_iso": ts_iso,
            })

    # 시간 오름차순 정렬
    out.sort(key=lambda r: (r.get("ts_epoch", 0.0), str(r.get("path", "")), str(r.get("event", ""))))
    return out


def write_timeline_csv(
    timeline_rows: List[Dict[str, Union[str, int, float, bool]]],
    csv_path: Union[str, Path],
) -> None:
    """
    build_timeline_rows 결과를 CSV로 저장 (UTF-8 with BOM; 엑셀 호환).
    """
    if not timeline_rows:
        # 빈 파일도 헤더는 쓰자
        fieldnames = ["ts_epoch", "ts_iso", "event", "path", "name", "parent", "size_bytes", "is_symlink"]
    else:
        # 키 집합을 합쳐서 안정적인 헤더를 만든다
        keys: List[str] = []
        seen = set()
        for r in timeline_rows:
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    keys.append(k)
        # 표준 컬럼을 앞으로
        preferred = ["ts_epoch", "ts_iso", "event", "path", "name", "parent", "size_bytes", "is_symlink"]
        fieldnames = preferred + [k for k in keys if k not in preferred]

    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(timeline_rows)


#파일 내부 함수


def _resolve_tzinfo(tz_offset_minutes: Optional[int]) -> timezone:
    """
    분 단위 오프셋으로 tzinfo를 만든다.
    - None  → 시스템 로컬 타임존
    - int   → 해당 오프셋의 고정 타임존
    """
    if tz_offset_minutes is None:
        # 시스템 로컬 타임존
        return datetime.now().astimezone().tzinfo or timezone.utc
    return timezone(timedelta(minutes=int(tz_offset_minutes)))


def _to_epoch_float(v: object) -> Optional[float]:
    try:
        f = float(v)  # None/"" 등은 예외
    except (TypeError, ValueError):
        return None
    # 0이나 음수 epoch은 비정상일 수 있어 drop_na==True면 제외
    if f <= 0:
        return None
    return f


def _epoch_to_iso(epoch: float, *, tzinfo: timezone, with_tz: bool = True) -> str:
    """
    epoch(UTC 기준)을 지정한 tzinfo 시각의 ISO 8601 문자열로 변환.
    - with_tz=True면 오프셋 포함 (예: 2025-10-02T11:22:33+09:00)
    """
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc).astimezone(tzinfo)
    if with_tz:
        return dt.isoformat(timespec="seconds")
    # 오프셋을 숨기고 ISO만
    return dt.replace(tzinfo=None).isoformat(timespec="seconds")
