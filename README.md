# 💚 ForensicFileAnalyzer : 포렌식 파일 분석 도구

[![tests](https://github.com/ahrdyrxkddhfl/ForensicFileAnalyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/ahrdyrxkddhfl/ForensicFileAnalyzer/actions/workflows/tests.yml)

증거 폴더를 스캔해 **파일 목록·해시·실제 형식·시간 정보**를 CSV로 기록하고, **확장자 위장**을 찾고, **수집 이후 변경·삭제·이동**을 검증하는 명령줄 도구입니다.

> EVI$ION 프로젝트로 시작해, 코드 리뷰에서 나온 탐지 누락·오탐 사례를 모두 재현 테스트(pytest)로 고정하며 보완했습니다.

## 1. 목적

파일 해시값 계산(MD5, SHA-256), 파일 시그니처 확인(매직 넘버로 실제 파일 형식 판별), 메타데이터 추출(생성·수정 시각 등), CSV 결과 저장, 키워드 검색 기능을 갖춘 파일 분석 도구를 만든다. 결과는 **재현 가능**하고, 도구가 **확인하지 못한 것도 숨기지 않고 기록**하는 것을 원칙으로 한다.

## 2. 기능

| 명령 | 하는 일 | 결과 |
|---|---|---|
| `inventory` | 파일 목록·크기·시간 수집, 선택적으로 해시(`--with-hash`)·시그니처(`--with-signature`) | `inventory_*.csv` |
| `search` | 텍스트 파일 키워드·정규식 검색(UTF-8, CP949, UTF-16 등) | `search_*.csv`, 검색 못 한 파일 `*_skipped.csv` |
| `timeline` | 생성·메타데이터 변경·수정·접근 시각을 시간순 사건으로 정렬 | `timeline_*.csv` |
| `validate` | 인벤토리 무결성 검사, 기준본(`--baseline`)과 비교해 변경·삭제·추가·이동 탐지 | `validate_*.csv` |

### ① 파일 인벤토리 & 메타데이터

- 경로, 루트 기준 상대 경로(`rel_path`), 크기, 수정·접근·메타데이터 변경·생성 시각을 기록한다.
- 시간 필드는 OS마다 뜻이 달라 정리해서 기록한다. Windows의 `st_ctime`은 **생성 시각**이므로 `birthtime_epoch`에 넣고, Unix의 `st_ctime`(메타데이터 변경 시각)만 `ctime_epoch`에 넣는다.
- 심볼릭 링크는 기본적으로 따라가지 않고 링크 자체를 기록한다(`is_symlink`, `link_target`, `link_broken`). `--follow-symlinks`로 따라갈 수 있으며, 이미 방문한 폴더를 (장치 번호, inode)로 기억해 순환 링크에서 멈추지 않는다.
- 읽지 못한 폴더·파일은 조용히 건너뛰지 않고 `*_errors.csv`로 남긴다.

### ② 해시 (MD5 + SHA-256, 선택 가능)

- 1MB 단위로 읽어 큰 파일도 처리하며, 여러 알고리즘을 한 번 읽기로 계산한다.
- `hash_status`로 결과 상태를 남긴다: `ok`, `read_error`(읽기 실패), `symlink_skipped`, `changed_during_hash`(수집과 해시 사이에 파일이 바뀜).

### ③ 파일 시그니처 & 확장자 위장 탐지

확장자가 아니라 **실제 바이트**로 형식을 판별한다. 확장자로 형식을 추측하면 위장을 탐지할 수 없기 때문이다.

1. libmagic(python-magic)이 있으면 libmagic으로 판별한다.
2. 없거나 libmagic이 "모름"이라고 하면 내장 매직 넘버 표로 판별한다: PNG, JPEG, GIF, PDF, ZIP, OLE(HWP·DOC), SQLite, 바이너리 plist, GZIP, 7z, RAR, ELF, **윈도우 실행 파일(MZ + PE 헤더 구조 확인)**, BMP, TIFF, WEBP·WAV·AVI(RIFF), MP4·MOV·HEIC(ftyp), FLAC, OGG, MP3(ID3).
3. 그래도 모르면 텍스트인지 판별한다(아래 "텍스트 판별").

| 사례 | 판정 |
|---|---|
| PNG 내용인 `photo.jpg`, 실행 파일인 `photo.jpg`, DOCX를 이름만 바꾼 `.txt` | 불일치 |
| 무작위(암호화) 바이트인 `secret.txt` | 불일치 |
| 앞은 텍스트, 뒤에 데이터를 붙인 `meeting_notes.txt` | 불일치(중간·끝 구간 표본 검사) |
| 헤더가 지워진 `.png`·`.pdf`·`.zip`·`.hwp` | 불일치 |
| HWP·DOC·`Thumbs.db`(OLE), APK·DOCX·HWPX(ZIP), `.py`·`.log`(텍스트) | 정상 |
| `.bin`·`.dat`에 담긴 알 수 없는 바이너리, 빈 파일 | 정상 |

**텍스트 판별**(`textutil.py`): 인코딩별로 실제 디코딩이 되는지와, 디코딩 결과의 **출력 가능 문자 비율**을 함께 본다. BOM → UTF-8 → CP949 → Shift-JIS → GBK → CP1252 → BOM 없는 UTF-16 순서다. BOM 없는 UTF-16은 ASCII 문자의 `0x00`이 한쪽 자리에 몰리는 분포나 한중일 문자 비율로 판별한다. 무작위 바이트 앞에 BOM만 붙여 텍스트로 위장하는 우회도 막는다. 테스트에서 100바이트 이상 무작위 데이터는 1,000개 중 0개가 텍스트로 오판됐다.

`sig_high_entropy`는 압축·암호화 수준의 엔트로피 구간이 있다는 **참고 정보**다. 정상 ZIP·JPEG도 True이므로 이것만으로 의심 파일로 보지 않는다.

### ④ 키워드 검색

- 인코딩: BOM → 지정 인코딩(기본 UTF-8 → CP949) → BOM 없는 UTF-16 순서로 읽고, 실제 사용한 인코딩을 `encoding` 열에 남긴다. 메모장 ANSI(CP949)·유니코드(UTF-16) 문서도 검색된다.
- 일부가 깨진 파일(텍스트 뒤에 데이터를 숨긴 위장 파일 등)도 텍스트 부분은 검색한다(`utf-8+replace`처럼 기록).
- 한 줄에 여러 번 나오면 각각 기록한다. 링크·10MB 초과·읽기 실패로 **검색하지 못한 파일은 `*_skipped.csv`에 이유와 함께** 남긴다.

### ⑤ 타임라인

- 파일마다 `Created` / `MetadataChanged` / `Modified` / `Accessed` 사건을 만들어 시간순으로 정렬한다. `--tz-offset-min 540`이면 KST로 표시한다.
- 0 이하(1970년 이전·초기화)이거나 현재보다 하루 이상 미래인 시각은 버리지 않고 `ts_suspicious=True`로 표시한다.

### ⑥ 검증 & 기준본 비교

수집 시점에 해시를 포함한 인벤토리를 **기준본**으로 저장해 두고, 나중에 `--baseline`으로 비교한다. 파일은 `rel_path`로 짝지으므로 증거 폴더를 다른 위치로 옮겨도 비교된다.

- 해시는 기준본과 현재 **양쪽에 값이 채워진** 알고리즘으로만 비교한다. 비교할 해시가 없으면 `BASELINE_NO_HASH`로 경고한다(크기·수정 시각까지 맞춘 변조는 해시 없이는 못 잡기 때문).
- 이동(`MOVED`)은 보수적으로 판정한다. 해시가 같은 후보가 양쪽에 **하나씩뿐**이고 **빈 파일이 아닐 때만** 이동으로 본다. 빈 파일이나 같은 내용의 복사본은 무엇이 어디로 갔는지 알 수 없으므로 삭제·추가로 그대로 둔다(삭제가 이동으로 묻히지 않게).
- macOS가 한글 파일명을 자모 분리형(NFD)으로 저장하는 경우를 고려해, 짝지을 때 유니코드 NFC로 정규화한다.
- 잘못된 입력(인벤토리가 아닌 기준본, `shake_128` 같은 해시, 없는 경로, 잘못된 정규식 등)은 **스캔을 시작하기 전에** 오류로 종료한다.

**이슈 코드**

| 코드 | 심각도 | 뜻 |
|---|---|---|
| `HASH_CHANGED` | ERROR | 기준본 대비 내용 변경 |
| `BASELINE_MISSING` | ERROR | 기준본에 있던 파일이 사라짐 |
| `FILE_NOT_FOUND` / `MISSING_FIELD` | ERROR | 검증 시점에 접근 불가 / 필수 값 누락 |
| `HASH_VERIFY_FAIL` | ERROR | 같은 실행 안에서 해시 재계산 결과가 다름(`--verify-hash`) |
| `BASELINE_NEW` / `MOVED` | WARN | 새로 생긴 파일 / 내용은 같고 경로만 바뀜 |
| `SIZE_CHANGED` / `MTIME_CHANGED` / `LINK_TARGET_CHANGED` | WARN | 크기·수정 시각·링크 대상 변경 |
| `BASELINE_NO_HASH` / `HASH_NOT_COMPARED` | WARN | 해시가 없어 내용 검증을 못 함(전체 / 파일 단위) |
| `EXT_MISMATCH` | WARN | 확장자와 실제 내용이 다름(위장 의심) |
| `TS_SUSPICIOUS` / `TS_FUTURE` | WARN | 0 이하 / 미래 시각(조작 의심) |
| `HASH_READ_FAIL` / `SIGNATURE_READ_FAIL` / `SCAN_ERROR` | WARN | 읽지 못해 확인하지 못함 |
| `CHANGED_DURING_HASH` | WARN | 수집과 해시 계산 사이에 파일이 바뀜 |
| `SIZE_MISMATCH` / `TS_BAD_TYPE` / `DUP_PATH` | WARN | 기록 불일치·형식 오류·중복 경로 |
| `LINK_BROKEN` | INFO | 대상이 없는 심볼릭 링크 |

### 결과 CSV 보안

파일명은 증거를 만든 사람이 마음대로 정할 수 있다. `=HYPERLINK(...)`처럼 엑셀 수식으로 시작하는 값은 앞에 `'`를 붙여 결과 CSV를 여는 분석가 PC에서 수식이 실행되지 않게 하고(CSV 수식 주입 방지), 기준본으로 다시 읽을 때는 원래 값으로 되돌린다. `--label`은 파일명에 안전한 문자만 남기며, 같은 초에 다시 실행해도 이전 결과를 덮어쓰지 않는다.

## 3. 설치 및 실행

```bash
# libmagic (선택: 없으면 내장 판별만 사용)
brew install libmagic            # macOS
sudo apt-get install libmagic1   # Ubuntu

pip install -r requirements.txt
python forensic_analyzer/dummy_test.py      # 테스트용 더미 증거 생성(고정 시드라 항상 같은 내용)

python main.py inventory ForensicTestData --with-hash --with-signature
python main.py search    ForensicTestData --kw error --kw 비밀번호
python main.py timeline  ForensicTestData --tz-offset-min 540
python main.py validate  ForensicTestData --with-hash --verify-hash --with-signature

# 변경 탐지: 수집 시점의 인벤토리를 기준본으로 저장해 두고 나중에 비교
python main.py inventory ForensicTestData --with-hash --out outputs/baseline.csv
python main.py validate  ForensicTestData --baseline outputs/baseline.csv
```

주요 옵션: `--exclude`(제외 글롭), `--follow-symlinks`, `--hash-algorithms sha256 sha1`, `--sig-no-magic`(내장 판별만), `--encodings utf-8 shift_jis`(검색 인코딩), `--max-size-mb`(검색 크기 상한), `--label`(파일명 라벨). 전체 목록은 `python main.py <명령> -h`.

## 4. 실행 결과 (더미 데이터)

**확장자 위장 탐지** (`inventory --with-signature`에서 `ext_mismatch=True`인 행)

| rel_path | sig_mime | sig_desc |
|---|---|---|
| docs/meeting_notes.txt | text/plain | 텍스트(utf-8) / 중간·끝 구간에 텍스트가 아닌 데이터 |
| docs/secret.txt | application/octet-stream | 알 수 없는 바이너리 |
| images/mismatch_signature.jpg | image/png | PNG image data, 1 x 1, 8-bit/color RGBA |

**인코딩별 검색** (`search --kw 비밀번호 --kw error`)

| 파일 | 줄 | 일치 | 인코딩 |
|---|---|---|---|
| docs/memo_cp949.txt | 2 | 비밀번호 | cp949 |
| docs/memo_utf16.txt | 2 | 비밀번호 | utf-16 |
| logs/app.log | 2 | ERROR | utf-8 |

**기준본 비교** — 기준본 저장 후 `notes.txt`를 같은 크기로 고치고 수정 시각을 되돌림, `table.csv`를 다른 폴더로 이동, `app.log`를 삭제

| severity | code | detail |
|---|---|---|
| WARN | MOVED | 경로 변경(내용 동일): docs/table.csv → table_moved.csv |
| ERROR | BASELINE_MISSING | 기준본에 있던 파일이 없음: logs/app.log |
| ERROR | HASH_CHANGED | sha256 변경: fd3e54cc45ee… → 82aad00bc8fd… |
| ERROR | HASH_CHANGED | md5 변경: fc34e963d171… → 27a95d90c107… |

## 5. 테스트

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

코드 리뷰에서 재현한 사례(위장 우회, 오탐, 변조 누락, 잘못된 입력)를 모두 테스트로 고정했다. libmagic이 설치된 환경에서는 libmagic 경로와 내장 판별 경로를 모두 검사한다. GitHub Actions에서 push마다 자동 실행된다.

| 파일 | 검사 내용 |
|---|---|
| `test_textutil.py` | 다국어·인코딩별 텍스트 인식, 무작위 바이트 오판률, BOM 우회 |
| `test_signature.py` | 잡아야 하는 위장 / 잡으면 안 되는 정상 파일, 읽기 실패 처리, 판정 규칙 |
| `test_inventory_hashing.py` | 정렬·상대 경로, 심볼릭 링크 정책, 순환 링크, OS별 시간 필드, 해시 상태 |
| `test_search_timeline.py` | 인코딩별 검색, 깨진 파일 검색, 건너뛴 파일 기록, 수상한 시각 |
| `test_validate.py` | 변조·이동·삭제 판정, 해시 없는 기준본, NFD 파일명, CSV 수식 주입 |
| `test_cli.py` | 잘못된 입력 사전 차단, 더미 데이터 전체 결과 |

## 6. 구조

```
main.py                      명령줄 진입점(입력 사전 검사)
forensic_analyzer/
  inventory.py               폴더 순회, 메타데이터, 심볼릭 링크 정책
  hashing.py                 해시 계산과 상태
  signature.py               매직 넘버·libmagic 판별, 확장자 위장 판정
  textutil.py                텍스트·인코딩 판별(시그니처와 검색이 공용)
  search.py                  키워드 검색
  timeline.py                타임라인
  validate.py                검증, 기준본 비교
  foroutput.py               CSV 저장(원자적 저장, 수식 주입 방지)
  dummy_test.py              테스트용 더미 증거 생성
tests/                       pytest
```

## 7. 한계

1. 파일 시스템 수준 분석이 아니므로 삭제된 파일 복구, NTFS 대체 데이터 스트림(ADS) 목록화는 하지 않는다.
2. PDF·Word 본문 검색은 지원하지 않는다.
3. 시각 조작은 명백한 경우(0 이하·미래)만 표시한다. 그럴듯한 과거 시각으로 바꾼 조작은 파일 시스템 메타데이터 비교(예: NTFS `$STANDARD_INFORMATION`과 `$FILE_NAME`)가 필요하다.
4. 분석 대상을 직접 읽으므로 접근 시각(atime)이 바뀔 수 있다. 원본이 아닌 사본이나 읽기 전용 마운트에서 실행해야 한다.
5. 256바이트 미만 파일은 무작위 데이터가 우연히 텍스트 조건을 통과할 수 있어 텍스트 판별 신뢰도가 낮다.
6. 검색 기본 인코딩은 한국어 위주다. GBK 중국어 문서는 CP949로도 디코딩되어 자동 구분이 안 되므로 `--encodings`로 지정해야 한다.
7. 텍스트 뒤 은닉 탐지는 앞·중간·끝 8KB씩 표본을 본다. 표본 사이에 숨긴 작은 데이터는 놓칠 수 있다.
8. libmagic 버전에 따라 세부 MIME 이름이 다를 수 있다. 허용 표에 없는 MIME이면 내장 판별 결과로 판정한다.
9. 대부분의 Linux에서는 생성 시각을 제공하지 않아 `birthtime_epoch`가 비어 있다.

## 8. 향후 보완점

1. 이미지(EXIF)·문서·압축 파일 내부 상세 분석
2. 디스크 이미지(E01, dd) 직접 분석
3. 검색 인덱스로 대용량 검색 속도 향상

### 관련 학습 내용 정리

- https://velog.io/@ahrdyrxkddhfl/파일-시스템
