# forensic_analyzer/timeline.py
"""파일 시간 정보로 타임라인(시간순 사건 목록)을 만든다.

파일 하나에서 생성·메타데이터 변경·수정·접근 시각을 각각 한 줄씩 사건으로
펼친 뒤 시간순으로 정렬한다. 여러 파일의 사건을 한 줄에 세우면 "무엇이 어떤
순서로 일어났는지"를 볼 수 있다.

시간 필드의 뜻은 OS마다 다르며, 인벤토리 단계(``inventory.platform_times``)에서
이미 정리해 두었다. 그래서 여기서는 필드 이름대로 라벨만 붙인다.

0 이하의 시각(1970-01-01 이전 또는 초기화된 값)과 현재보다 하루 이상 미래인 시각은
버리지 않고 기록하되 ``ts_suspicious=True``로 표시한다. 시각을 조작한 흔적일 수 있기
때문이다(``validate``의 ``TS_SUSPICIOUS``·``TS_FUTURE``와 같은 기준).
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Union

Value = Union[str, int, float, bool, None]

# 현재보다 이만큼(초) 이상 미래인 시각은 수상한 시각으로 표시한다.
FUTURE_TOLERANCE_SEC = 86400

TIMELINE_FIELDS: Tuple[str, ...] = (
    "ts_epoch", "ts_iso", "event", "ts_suspicious", "path", "rel_path", "name", "size_bytes", "is_symlink",
)


@dataclass(frozen=True)
class EventSpec:
    """인벤토리 시간 열 하나를 타임라인 사건 하나로 바꾸는 규칙.

    Attributes:
        field: 인벤토리 열 이름(예: ``mtime_epoch``).
        label: 타임라인 사건 이름(예: ``Modified``).
    """

    field: str
    label: str


DEFAULT_EVENTS: Tuple[EventSpec, ...] = (
    EventSpec("birthtime_epoch", "Created"),
    EventSpec("ctime_epoch", "MetadataChanged"),
    EventSpec("mtime_epoch", "Modified"),
    EventSpec("atime_epoch", "Accessed"),
)


def build_timeline_rows(
    rows: List[Dict[str, Value]],
    *,
    events: Tuple[EventSpec, ...] = DEFAULT_EVENTS,
    tz_offset_minutes: Optional[int] = None,
    emit_inventory_fields: Tuple[str, ...] = ("path", "rel_path", "name", "size_bytes", "is_symlink"),
) -> List[Dict[str, Value]]:
    """인벤토리 행을 사건 행으로 펼쳐 시간순으로 정렬한다.

    Args:
        rows: ``collect_inventory`` 결과.
        events: 사건으로 만들 시간 열과 라벨.
        tz_offset_minutes: 표시 시간대(분). None이면 이 PC의 시간대, 0이면 UTC,
            540이면 KST(UTC+9).
        emit_inventory_fields: 사건 행에 함께 복사할 인벤토리 열.

    Returns:
        사건 행 리스트(시간 오름차순). 열은 ``TIMELINE_FIELDS``다.
        시각 값이 비어 있거나 숫자가 아니면 그 사건은 만들지 않는다.

    Raises:
        ValueError: ``tz_offset_minutes``가 ±24시간 범위를 벗어날 때.

    Example:
        >>> build_timeline_rows([{"path": "a", "mtime_epoch": 0.0}], tz_offset_minutes=0)[0]["ts_iso"]
        '1970-01-01T00:00:00+00:00'
    """
    tzinfo = resolve_tzinfo(tz_offset_minutes)
    future_limit = time.time() + FUTURE_TOLERANCE_SEC
    out: List[Dict[str, Value]] = []
    for row in rows:
        base = {k: row.get(k) for k in emit_inventory_fields}
        for spec in events:
            epoch = _to_epoch(row.get(spec.field))
            if epoch is None:
                continue
            out.append({
                **base,
                "event": spec.label,
                "ts_epoch": epoch,
                "ts_iso": _epoch_to_iso(epoch, tzinfo),
                "ts_suspicious": epoch <= 0 or epoch > future_limit,
            })
    out.sort(key=lambda r: (float(r["ts_epoch"]), str(r.get("path", "")), str(r.get("event", ""))))
    return out


def resolve_tzinfo(tz_offset_minutes: Optional[int]) -> timezone:
    """분 단위 오프셋으로 시간대 객체를 만든다.

    Args:
        tz_offset_minutes: None이면 이 PC의 시간대, 정수면 고정 오프셋.

    Returns:
        ``datetime.timezone`` 또는 이 PC의 시간대 객체.

    Raises:
        ValueError: 오프셋이 -1439~1439분 범위를 벗어날 때.
    """
    if tz_offset_minutes is None:
        return datetime.now().astimezone().tzinfo or timezone.utc
    if not -1439 <= int(tz_offset_minutes) <= 1439:
        raise ValueError("시간대 오프셋은 -1439~1439분 사이여야 합니다")
    return timezone(timedelta(minutes=int(tz_offset_minutes)))


def _to_epoch(v: Value) -> Optional[float]:
    """값을 epoch(float)로 바꾼다. 비어 있거나 숫자가 아니거나 NaN·무한대면 None.

    Args:
        v: 인벤토리 시간 값.

    Returns:
        epoch 초 또는 None.
    """
    if v is None or v == "" or isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _epoch_to_iso(epoch: float, tzinfo: timezone) -> str:
    """epoch를 지정 시간대의 ISO 8601 문자열로 바꾼다.

    OS가 표현할 수 없는 시각(아주 먼 과거·미래)은 빈 문자열을 반환한다.

    Args:
        epoch: epoch 초.
        tzinfo: 표시 시간대.

    Returns:
        예: ``2025-10-02T11:22:33+09:00``. 변환할 수 없으면 빈 문자열.
    """
    try:
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=epoch)
        return dt.astimezone(tzinfo).isoformat(timespec="seconds")
    except (OverflowError, ValueError, OSError):
        return ""
