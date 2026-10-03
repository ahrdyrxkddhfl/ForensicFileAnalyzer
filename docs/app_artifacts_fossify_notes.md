# 앱 아티팩트 명세: Fossify Notes (안드로이드 메모 앱)

앱에서 행동을 하나씩 하고, 행동 전후의 앱 데이터 폴더를 `appdiff`로 비교해
"이 행동을 하면 이 파일의 이 부분이 생기거나 바뀐다"를 정리했다. 비교에 쓴 수집본은
[samples/fossify_notes](../samples/fossify_notes)에 있어 같은 결과를 다시 만들 수 있다.

## 1. 환경

| 항목 | 값 |
|---|---|
| 기기 | 안드로이드 에뮬레이터, Android 14(API 34) `google_apis` arm64 이미지(userdebug, `adb root` 가능) |
| 앱 | Fossify Notes 1.7.0(versionCode 13), F-Droid 공식 APK(`org.fossify.notes_13.apk`, SHA-256 `5a56e0e39cc488e1f3b947d3801006d3b7450ec73c67f03195c64c5fd3b6bced`). 오픈소스 메모 앱 |
| 수집 | 행동마다 `am force-stop`으로 앱을 종료한 뒤 `adb pull -a /data/data/org.fossify.notes` |
| 분석 | `python main.py appdiff <후> --before <전>` |

앱을 강제 종료하면 SQLite가 WAL을 본 DB 파일에 합칠 기회 없이 끝난다. 실행 중이던
기기를 압수했을 때와 비슷한 상태다.

## 2. 저장 위치

| 파일 | 내용 |
|---|---|
| `databases/notes.db` (+ `-wal`, `-shm`) | 메모. `notes` 테이블(`id`, `title`, `value`=본문, `type`, `path`, `protection_type`, `protection_hash`) |
| `shared_prefs/Prefs.xml` | 앱 설정과 사용 흔적(실행 횟수, 현재 메모, 마지막 사용 시각, 잠금 해제 실패 횟수 등) |
| `files/profileInstalled` 등 | 안드로이드 런타임이 만드는 파일. 사용자 행동과 무관 |

## 3. 행동별 아티팩트

| 행동 | 파일 | 변화 |
|---|---|---|
| 설치 | 데이터 폴더 | 빈 `cache/`, `code_cache/`만 생김 |
| 첫 실행 | `notes.db` | 테이블 5개 생성. `notes`에 기본 메모 1행(`General note`, 본문 없음) |
| | `Prefs.xml` | 키 11개 생성(`app_run_count=1`, `current_note_id=1` 등) |
| 메모 작성(제목 `Meeting`) | `notes.db` › `notes` | 행 추가: `id=2, title=Meeting, value=Budget review at 3pm with Kim` |
| | `notes.db` › `sqlite_sequence` | `seq` 1 → 2(지금까지 쓴 가장 큰 메모 번호. 삭제해도 줄지 않음) |
| | `Prefs.xml` | `current_note_id` 1 → 2, `last_created_note_type` 추가 |
| 메모 수정 | `notes.db` › `notes` | `id=2`의 `value`만 변경(뒤에 ` moved to 4pm` 추가) |
| 메모 삭제 | `notes.db` › `notes` | `id=2` 행 삭제 |
| | `Prefs.xml` | `current_note_id` 2 → 1, `widget_note_id` 추가 |
| 메모 잠금(PIN) | `notes.db` › `notes` | `protection_type` -1 → 1(PIN), `protection_hash`에 40자리 16진수 |
| | `Prefs.xml` | `password_retry_count=0`, `password_count_down_start_ms=0` 추가(잠금 해제 실패 횟수·대기) |
| 본문 있는 메모 작성 후 잠금 | `notes.db` › `notes` | 행 추가: `title=Secret, value=bank account pin 9876, protection_type=1` |
| 모든 실행 | `Prefs.xml` | `app_run_count` +1, `last_unlock_timestamp_ms`가 그 실행 시각(밀리초)으로 갱신 |

메모 작성부터 끝까지 본 DB 파일 `notes.db`는 한 번도 바뀌지 않았다. 바뀐 것은
`notes.db-wal`과 `notes.db-shm`뿐이다(아래 발견 1).

## 4. 발견

### 1) 메모 내용은 전부 WAL 파일에만 있다

첫 실행 후 `notes.db`는 4,096바이트로 헤더뿐이고, 테이블과 메모는 모두
`notes.db-wal`(61,832바이트)에 있었다. 본 DB 파일만 복사하거나 열면 메모가 하나도
보이지 않는다. 수집할 때는 `-wal`·`-shm`을 반드시 함께 가져와야 하고, 분석할 때는
WAL을 반영해야 한다. `appdiff`는 DB와 `-wal`을 임시 사본으로 함께 열어 이를 처리한다.

### 2) 수정 전·삭제된 메모가 WAL에 남는다

WAL은 덮어쓰지 않고 바뀐 페이지를 뒤에 이어 쓴다. 메모를 고치고 지운 뒤에도
`notes.db-wal`의 원시 바이트에는 수정 전 본문과 수정 후 본문이 그대로 있었다.

| 수집 시점 | `at 3pm with Kim` 출현 | `moved to 4pm` 출현 | 현재 DB 상태 |
|---|---|---|---|
| 작성 후 | 1 | 0 | 메모 있음 |
| 수정 후 | 2 | 1 | 수정본만 보임 |
| 삭제 후 | 2 | 1 | 메모 없음 |
| 마지막 수집(잠금 2회 후) | 2 | 1 | 메모 없음 |

앱 화면과 DB의 현재 상태로는 삭제된 메모지만, WAL의 이전 프레임에서 복구할 수 있다.
체크포인트(WAL을 본 파일에 합치고 비우는 일)가 일어나면 사라질 수 있으므로, 앱을
실행하지 않은 채 빨리 수집하는 것이 중요하다. `appdiff`는 현재 상태끼리 비교하므로 이
흔적은 직접 보여 주지 않는다(위 표는 원시 바이트 검색으로 확인).

### 3) 잠금 PIN은 솔트 없는 SHA-1이라 즉시 복원된다

PIN `1234`로 잠근 메모의 `protection_hash`는 `7110eda4d09e062aa5e4a390b0a572ac0d2c0220`이고,
이는 `sha1("1234")`와 같다. 솔트가 없으므로 4자리 PIN 10,000개를 모두 대입하면 바로
찾는다(실측: `0000`~`9999` 중 `1234` 하나 일치).

### 4) 잠긴 메모의 본문은 평문이다

잠근 메모 `Secret`의 본문 `bank account pin 9876`이 `value` 열에 그대로 저장되어 있었다.
잠금은 앱 화면에서 본문을 가리는 기능일 뿐 데이터를 암호화하지 않는다. DB를 확보하면
PIN 없이 본문을 읽을 수 있다.

삭제 흔적은 하나 더 있다. `sqlite_sequence`의 `seq`는 지금까지 쓴 가장 큰 메모 번호라
삭제해도 줄지 않는다. 마지막 수집본에서 `seq=3`인데 남은 메모는 `id` 1, 3뿐이므로, 2번
메모가 있었다가 지워졌다는 것을 WAL을 보지 않고도 알 수 있다.

### 5) 설정 파일이 사용 이력을 남긴다

`app_run_count`는 앱을 열 때마다 1씩 늘었다. `last_unlock_timestamp_ms`는 실행할 때마다
그 시각(Unix 밀리초)으로 갱신되어, 마지막으로 앱을 연 시각으로 볼 수 있다. 예: `1790987644922` → 2026-10-03 09:34:04 KST. 메모 테이블에는 작성·수정
시각 열이 없으므로, 언제 앱을 썼는지는 이 값과 파일 시각으로 추정해야 한다.

## 5. 재현

```bash
# 수집본끼리 비교(저장소에 포함)
python main.py appdiff samples/fossify_notes/s3_note_edited --before samples/fossify_notes/s2_note_created

# 직접 수집할 때(에뮬레이터, google_apis 이미지)
adb root
adb install fossify_notes.apk
# ... 앱에서 행동 ...
adb shell am force-stop org.fossify.notes
adb pull -a /data/data/org.fossify.notes snapshots/<단계>/
```

| 수집본 | 직전 행동 |
|---|---|
| `s1_first_launch` | 설치 후 첫 실행 |
| `s2_note_created` | 메모 `Meeting` 작성 |
| `s3_note_edited` | 본문 수정 |
| `s4_note_deleted` | 메모 삭제 |
| `s5_note_locked` | 기본 메모를 PIN `1234`로 잠금 |
| `s6_secret_locked` | 메모 `Secret` 작성 후 PIN `1234`로 잠금 |

수집본에서는 런타임이 만드는 `cache/oat_primary/`(컴파일된 앱 코드)를 뺐다. 설치
직후 수집본은 빈 폴더뿐이라 저장소에 넣지 않았다.

## 6. 한계

- 에뮬레이터에서 root로 수집했다. 실기기는 루팅이나 백업 등 다른 수집 방법이 필요하다.
- 한 버전(1.7.0)만 확인했다. 앱이 업데이트되면 테이블 구조나 저장 방식이 바뀔 수 있다. 다시 실험할 때는 위 SHA-256으로 같은 APK인지 확인한다. 시각·WAL 크기·해시 값은 실험마다 달라지지만 발견 1~5는 같은 버전이면 재현된다.
- `adb shell input`은 영문만 입력할 수 있어 메모 내용을 영문으로 썼다.
- 체크포인트가 일어난 뒤의 WAL 잔존 여부, 체크리스트형 메모, 패턴 잠금은 확인하지 않았다.
