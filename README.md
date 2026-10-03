# 💚 ForensicFileAnalyzer : 포렌식 파일 분석 도구

[![tests](https://github.com/ahrdyrxkddhfl/ForensicFileAnalyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/ahrdyrxkddhfl/ForensicFileAnalyzer/actions/workflows/tests.yml)

증거 폴더를 스캔해 **파일 목록·해시·실제 형식·시간 정보**를 CSV로 기록하고, **확장자 위장**을 찾고, **수집 이후 변경·삭제·이동**을 검증하는 명령줄 도구입니다. 폴더 안의 **앱 패키지(APK·IPA)**를 확장자와 상관없이 찾아 패키지명·버전·권한도 기록합니다.

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
| `apps` | APK·IPA를 확장자와 상관없이 찾아 패키지명·버전·SDK·권한·서명 정보 추출 | `apps_*.csv` |
| `appdiff` | 앱 행동 전후 데이터 폴더 비교: 파일 추가·삭제·변경과 SQLite 행·설정 키 단위 변화 | `appdiff_*.csv` |

### ① 파일 인벤토리 & 메타데이터

- 경로, 루트 기준 상대 경로(`rel_path`), 크기, 수정·접근·메타데이터 변경·생성 시각을 기록한다.
- 시간 필드는 OS마다 뜻이 달라 정리해서 기록한다. Windows의 `st_ctime`은 **생성 시각**이므로 `birthtime_epoch`에 넣고, Unix의 `st_ctime`(메타데이터 변경 시각)만 `ctime_epoch`에 넣는다.
- 심볼릭 링크는 기본적으로 따라가지 않고 링크 자체를 기록한다(`is_symlink`, `link_target`, `link_broken`). `--follow-symlinks`로 따라갈 수 있으며, 이미 방문한 폴더를 (장치 번호, inode)로 기억해 순환 링크에서 멈추지 않는다.
- 읽지 못한 폴더·파일은 조용히 건너뛰지 않고 `*_errors.csv`로 남긴다. 순환 링크를 막은 기록은 오류와 구분해 따로 표시한다.
- 결과 폴더가 스캔 대상 안에 있으면(예: 루트를 `.`로 준 경우) 자동으로 제외해, 이전 결과 CSV가 인벤토리에 섞이지 않게 한다.
- 인벤토리를 저장할 때 **스캔 정보**(`<이름>.meta.json`: 도구 버전, 수집 시각, 루트, 링크·제외 옵션, 해시 알고리즘, 실행 환경)를 함께 남긴다.

### ② 해시 (MD5 + SHA-256, 선택 가능)

- 1MB 단위로 읽어 큰 파일도 처리하며, 여러 알고리즘을 한 번 읽기로 계산한다.
- `hash_status`로 결과 상태를 남긴다: `ok`, `read_error`(읽기 실패), `symlink_skipped`, `changed_during_hash`(수집과 해시 사이에 파일이 바뀜).

### ③ 파일 시그니처 & 확장자 위장 탐지

확장자가 아니라 **실제 바이트**로 형식을 판별한다. 확장자로 형식을 추측하면 위장을 탐지할 수 없기 때문이다.

0. ZIP(`PK`로 시작)이면 libmagic을 쓰지 않고 **ZIP 안을 열어 내부 구조로** 판별한다. APK·IPA·DOCX·HWPX는 앞부분 시그니처가 모두 ZIP과 같아서, 형식마다 반드시 있어야 하는 내부 파일을 확인해야 구분된다(아래 "ZIP 내부 구조").
1. libmagic(python-magic)이 있으면 libmagic으로 판별한다.
2. 없거나 libmagic이 "모름"이라고 하면 내장 매직 넘버 표로 판별한다: PNG, JPEG, GIF, PDF, ZIP, OLE(HWP·DOC), SQLite, 바이너리 plist, GZIP, 7z, RAR, ELF, **윈도우 실행 파일(MZ + PE 헤더 구조 확인)**, BMP, TIFF(카메라 RAW 포함), WEBP·WAV·AVI(RIFF), MP4·MOV·HEIC·AVIF·CR3(ftyp), FLAC, OGG, MP3(ID3).
3. 그래도 모르면 텍스트인지 판별한다(아래 "텍스트 판별").

| 사례 | 판정 |
|---|---|
| PNG 내용인 `photo.jpg`, 실행 파일(EXE·ELF)인 `photo.jpg`, DOCX를 이름만 바꾼 `.txt` | 불일치 |
| 무작위(암호화) 바이트인 `secret.txt` | 불일치 |
| 앞은 텍스트, 뒤에 데이터를 붙인 `meeting_notes.txt` | 불일치(중간·끝 구간 표본 검사) |
| 헤더가 지워진 `.png`·`.pdf`·`.zip`·`.hwp` | 불일치 |
| 일반 ZIP·워드 문서를 이름만 바꾼 `.apk`·`.ipa`, 진짜 APK를 바꾼 `.docx` | 불일치(ZIP 내부 구조 확인) |
| 매니페스트가 텍스트이거나 `classes.dex`가 DEX가 아닌 `.apk` | 불일치(내부 파일도 이름만 믿지 않음) |
| 확장자를 떼어 숨긴 사진·영상·음성·PDF | 불일치 |
| HWP·DOC·`Thumbs.db`(OLE), 구조가 확인된 APK·IPA·DOCX·HWPX(ZIP), `.py`·`.log`(텍스트) | 정상 |
| DEX가 없는 분할 APK, APK·DOCX를 `.zip`으로 둔 것(ZIP인 것은 사실) | 정상(`sig_mime`·`sig_desc`에 내부 형식 표시) |
| 확장자 없는 리눅스 실행 파일(`ls`), `libc.so.6`, `mod.ko`, 카메라 RAW(`.CR2`·`.NEF`·`.DNG`) | 정상 |
| `.bin`·`.dat`에 담긴 알 수 없는 바이너리, 빈 파일 | 정상 |
| 이 도구가 모르는 확장자(예: `.xyz`) | 판정 불가(불일치로 보지 않음) |

허용 확장자 목록 방식은 모든 형식을 다 담을 수 없다. 그래서 근거가 있을 때만 불일치로 판정하고, 도구가 모르는 확장자는 "판정 불가"로 둔다. 불일치 경고가 너무 많으면 진짜 위장이 묻히기 때문이다.

**ZIP 내부 구조**(`container.py`): 내부 파일도 이름만으로는 믿지 않는다. 앱 패키지는 핵심 파일의 앞부분 바이트까지 확인한다. 판별 근거는 `sig_source=container`, `sig_desc`에 남는다.

| 형식 | 확인하는 것 |
|---|---|
| APK | `AndroidManifest.xml`이 빌드 때 컴파일된 바이너리 XML(`03 00 08 00`). `classes*.dex`가 있으면 `dex\n`으로 시작(DEX가 없는 분할 APK도 있어 필수는 아님) |
| IPA | `Payload/<앱>.app/Info.plist`가 있고 내용이 plist(`bplist00` 또는 XML) |
| DOCX·XLSX·PPTX | `[Content_Types].xml`과 본문 폴더(`word/`·`xl/`·`ppt/`) |
| HWPX·ODT·ODS·ODP·EPUB | 내부 파일 `mimetype`에 적힌 형식 이름 |

다음 경우는 앱·문서로 인정하지 않되, "아니다"와 구분해 이유를 남긴다.

- 끝이 잘려 ZIP 구조를 읽을 수 없음
- 핵심 파일을 읽을 수 없음(암호화 플래그·지원하지 않는 압축 방식). 안드로이드는 이런 조작을 무시하고 설치하지만 분석 도구는 막히므로, 악성 앱의 분석 방해 기법일 수 있다.
- 같은 이름의 내부 파일이 여러 개(어느 것을 판정했는지 보장할 수 없어 변조 의심으로 표시)

APK·DOCX를 `.zip`으로 둔 것을 정상으로 보는 것은 의도한 정책이다. `.zip`은 거짓 확장자가 아니고, 앱인지는 `sig_mime`으로 확인할 수 있다. libmagic 환경에서는 이전에 이 경우가 불일치로 나왔을 수 있다.

**텍스트 판별**(`textutil.py`): 인코딩별로 실제 디코딩이 되는지와, 디코딩 결과의 **출력 가능 문자 비율**을 함께 본다. BOM → UTF-8 → CP949 → Shift-JIS → GBK → CP1252 → BOM 없는 UTF-16 순서다. BOM 없는 UTF-16은 두 바이트 순서로 모두 읽어 보고, 디코딩 결과가 그럴듯한 글자(ASCII·한중일 문자 등)로 이뤄진 쪽을 고른다. 무작위 바이트 앞에 BOM만 붙여 텍스트로 위장하는 우회도 막는다. 로그 중간이 0으로 채워진 구간은 떼어 놓고 판단한다. 테스트에서 100바이트 이상 무작위 데이터는 1,000개 중 0개가 텍스트로 오판됐다.

`sig_high_entropy`는 압축·암호화 수준의 엔트로피 구간이 있다는 **참고 정보**다. 정상 ZIP·JPEG도 True이므로 이것만으로 의심 파일로 보지 않는다.

### ④ 키워드 검색

- 인코딩: 시그니처 판별과 **같은 함수·같은 기본 목록**으로 인코딩을 고른다. 메모장 ANSI(CP949)·유니코드(UTF-16) 문서, 일본어(Shift-JIS) 문서도 기본값으로 검색된다.
- 파일 전체가 UTF-8로 읽히지 않으면 **줄 단위로** 인코딩을 골라 읽고, 결과의 `encoding` 열에 그 줄의 인코딩을 남긴다. 줄마다 UTF-8을 먼저 시도하고, 그다음은 **UTF-8로 읽히지 않는 줄만 모아 판정한** 파일의 대표 인코딩을 시도한다. 앞부분은 영문이고 뒤에 CP949 한글이 나오는 윈도우 로그, UTF-8 줄과 CP949(또는 Shift-JIS) 줄이 번갈아 섞인 로그에서도 한글을 놓치지 않는다.
- 같은 바이트가 여러 인코딩으로 동시에 읽히는 경우(예: 일본어 Shift-JIS 바이트가 CP949로 `듖뿚롌`처럼 읽힘)는 디코딩 결과가 어색한지 확인해 가려낸다. CP949는 상용 한글 2,350자 비율, Shift-JIS는 반각 가타카나 비율을 본다.
- 줄 번호는 편집기와 같게 `\n`·`\r\n`·`\r`에서만 센다(폼피드 등에서 줄 번호가 밀리지 않음).
- 끝이 잘린 파일이나 일부가 깨진 파일(텍스트 뒤에 데이터를 숨긴 위장 파일 등)도 멈추지 않고 텍스트 부분을 검색한다. 어떤 인코딩으로도 안 되는 부분만 `utf-16+replace`처럼 표시한다.
- 한 줄에 여러 번 나오면 각각 기록한다. 링크·10MB 초과·읽기 실패로 **검색하지 못한 파일은 `*_skipped.csv`에 이유와 함께** 남긴다.

### ⑤ 타임라인

- 파일마다 `Created` / `MetadataChanged` / `Modified` / `Accessed` 사건을 만들어 시간순으로 정렬한다. `--tz-offset-min 540`이면 KST로 표시한다.
- 0 이하(1970년 이전·초기화)이거나 현재보다 하루 이상 미래인 시각은 버리지 않고 `ts_suspicious=True`로 표시한다.

### ⑥ 검증 & 기준본 비교

수집 시점에 해시를 포함한 인벤토리를 **기준본**으로 저장해 두고, 나중에 `--baseline`으로 비교한다. 파일은 `rel_path`로 짝지으므로 증거 폴더를 다른 위치로 옮겨도 비교된다.

- 해시는 기준본과 현재 **양쪽에 값이 채워진** 알고리즘으로만 비교한다. 비교할 해시가 없으면 `BASELINE_NO_HASH`로 경고한다(크기·수정 시각까지 맞춘 변조는 해시 없이는 못 잡기 때문).
- 이동(`MOVED`)은 보수적으로 판정한다. 해시가 같은 후보가 양쪽에 **하나씩뿐**이고 **빈 파일이 아닐 때만** 이동으로 본다. 빈 파일이나 같은 내용의 복사본은 무엇이 어디로 갔는지 알 수 없으므로 삭제·추가로 그대로 둔다(삭제가 이동으로 묻히지 않게).
- macOS가 한글 파일명을 자모 분리형(NFD)으로 저장하는 경우를 고려해, 짝지을 때 유니코드 NFC로 정규화한다.
- 기준본의 스캔 정보(`.meta.json`)와 지금 옵션을 비교한다. 링크 따라가기·제외 옵션이 다르면 `BASELINE_OPTIONS_DIFFER`로 먼저 알려, 옵션 차이 때문에 생긴 추가·삭제를 실제 변경으로 오해하지 않게 한다.
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
| `HASH_READ_FAIL` / `HASH_VERIFY_READ_FAIL` / `SIGNATURE_READ_FAIL` / `SCAN_ERROR` | WARN | 읽지 못해 확인하지 못함(`HASH_VERIFY_READ_FAIL`은 `--verify-hash` 재계산 시) |
| `CHANGED_DURING_HASH` | WARN | 수집과 해시 계산 사이에 파일이 바뀜 |
| `SIZE_MISMATCH` / `TS_BAD_TYPE` / `DUP_PATH` | WARN | 기록 불일치·형식 오류·중복 경로 |
| `BASELINE_OPTIONS_DIFFER` | WARN | 기준본과 스캔 옵션(링크·제외)이 다름 |
| `LINK_BROKEN` / `SYMLINK_CYCLE_SKIPPED` | INFO | 대상이 없는 심볼릭 링크 / 순환 링크를 막음 |
| `BASELINE_META_MISSING` | INFO | 기준본의 스캔 정보가 없어 옵션 비교를 못 함 |

### ⑦ 앱 패키지 정보

ZIP 내부 구조(③)로 APK·IPA를 찾으므로 `.zip`으로 둔 앱도 목록에 나온다. 무슨 앱인지(패키지명·번들 ID, 버전)와 무엇을 요구하는지(권한)를 한 줄씩 기록하고, `--with-hash`면 해시도 함께 남겨 악성 앱 정보 조회에 쓸 수 있게 한다.

| 열 | APK | IPA |
|---|---|---|
| `package` | 패키지명 | `CFBundleIdentifier`(번들 ID) |
| `version_name` / `version_code` | `versionName` / `versionCode` | `CFBundleShortVersionString` / `CFBundleVersion` |
| `min_os` / `target_sdk` | 최소·대상 SDK | `MinimumOSVersion` / `DTPlatformVersion` |
| `permissions` | 요청 권한(`uses-permission`) | 권한 사유 키(`NS...UsageDescription`) |
| `signing` | 서명 방식(`v1`·`v2`·`v3`) | 서명 파일 유무(`code_signature`·`provisioning_profile`) |

- APK 매니페스트는 빌드 때 바이너리 XML로 컴파일되어 직접 해석하기 어려우므로 오픈소스 **androguard**로 읽는다. IPA의 `Info.plist`는 표준 라이브러리 `plistlib`으로 읽는다(XML·바이너리 plist 모두).
- 암호화 플래그·지원하지 않는 압축 방식처럼 분석을 방해하는 ZIP 조작이 있어도, 안드로이드처럼 읽어 정보를 뽑는다. 이때 `structure_ok=False`와 구조 확인 결과(`structure_desc`)를 함께 남긴다.
- 확장자가 `.apk`·`.ipa`인 파일은 결과에서 빼지 않는다. 앱 표식이 없으면 `status=not_app`, 파일이나 정보를 읽지 못하면 `parse_error`로 남긴다.

### ⑧ 앱 행동 전후 비교 (아티팩트 명세)

앱에서 메모 작성 같은 행동을 하기 전과 후에 앱 데이터 폴더를 각각 수집해 두고 비교하면, "이 행동을 하면 이 파일의 이 부분이 생기거나 바뀐다"를 찾을 수 있다.

```bash
python main.py appdiff snapshots/after --before snapshots/before
```

| 대상(앞부분 바이트로 판별) | 비교 단위 | `change` |
|---|---|---|
| 모든 파일 | `rel_path`로 짝지어 SHA-256 비교 | `FILE_ADDED` / `FILE_DELETED` / `FILE_MODIFIED` |
| SQLite DB | 테이블별 행(rowid, 없으면 기본 키로 짝지음). 변경은 열 단위 | `TABLE_ADDED` / `ROW_ADDED` / `ROW_DELETED` / `ROW_CHANGED` |
| 설정 XML(`shared_prefs`의 `<map>`) | 키(값에 타입 포함, 예: `boolean:true`) | `KEY_ADDED` / `KEY_DELETED` / `KEY_CHANGED` |
| plist(XML·바이너리) | 중첩 키를 `a.b[0]` 경로로 펼친 키 | 위와 같음 |

- **WAL 반영**: 안드로이드 앱 DB는 대부분 WAL 모드라 최근 변경이 `-wal` 파일에 먼저 쌓인다. 본 DB 파일만 읽으면 방금 쓴 메모가 보이지 않는다. 그래서 DB와 `-wal`을 함께 읽고, `-wal`만 바뀐 경우도 본 DB의 행 변화로 보여 준다.
- **원본을 열지 않음**: SQLite는 DB를 열면 옆에 `-shm`을 만들고, 닫을 때 WAL을 본 파일에 합친다. 원본을 직접 열면 증거가 바뀌므로 임시 사본에서 연다(테스트로 원본이 바이트 단위로 그대로인지 확인).
- 깨진 DB·설정 파일은 멈추지 않고 `PARSE_ERROR`로 남긴다. 값이 길면 앞 300자와 원래 길이를, BLOB은 16진수로 남긴다.

**실제 앱으로 만든 명세**: 안드로이드 에뮬레이터에서 오픈소스 메모 앱 Fossify Notes로 작성·수정·삭제·잠금을 하고 행동마다 수집해 비교했다 → [docs/app_artifacts_fossify_notes.md](docs/app_artifacts_fossify_notes.md). 수집본은 [samples/fossify_notes](samples/fossify_notes)에 있다. 확인한 것:

- 메모 내용은 전부 `notes.db-wal`에 있고 본 DB 파일은 헤더뿐이다(WAL을 빼면 메모가 하나도 안 보임).
- 수정 전·삭제된 메모 본문이 WAL의 이전 프레임에 원시 바이트로 남는다.
- 메모 잠금 PIN은 솔트 없는 SHA-1로 저장되어 4자리 PIN이 즉시 복원되고, 잠긴 메모의 본문은 평문이다.

### 결과 CSV 보안

파일명은 증거를 만든 사람이 마음대로 정할 수 있다. `=HYPERLINK(...)`처럼 엑셀 수식으로 시작하는 값은 앞에 `'`를 붙여 결과 CSV를 여는 분석가 PC에서 수식이 실행되지 않게 하고(CSV 수식 주입 방지), 기준본으로 다시 읽을 때는 원래 값으로 되돌린다. 원래부터 `'`로 시작하는 파일명에도 `'`를 하나 더 붙여, 되돌릴 때 원래 이름과 정확히 같아지게 한다. `--label`은 파일명에 안전한 문자만 남기며, 같은 초에 다시 실행해도 이전 결과를 덮어쓰지 않는다.

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
python main.py apps      ForensicTestData --with-hash
python main.py appdiff   snapshots/after --before snapshots/before   # 앱 행동 전후 수집본 비교

# 변경 탐지: 수집 시점의 인벤토리를 기준본으로 저장해 두고 나중에 비교
python main.py inventory ForensicTestData --with-hash --out outputs/baseline.csv
python main.py validate  ForensicTestData --baseline outputs/baseline.csv
```

주요 옵션: `--exclude`(제외 글롭), `--follow-symlinks`, `--hash-algorithms sha256 sha1`, `--sig-no-magic`(내장 판별만), `--encodings utf-8 gbk`(검색 인코딩), `--max-size-mb`(검색 크기 상한), `--label`(파일명 라벨). 전체 목록은 `python main.py <명령> -h`.

인벤토리를 저장하면 같은 이름의 `.meta.json`이 함께 생긴다. 기준본으로 쓸 CSV는 이 파일과 함께 보관해야 옵션 비교가 된다.

## 4. 실행 결과 (더미 데이터)

**확장자 위장 탐지** (`inventory --with-signature`에서 `ext_mismatch=True`인 행)

| rel_path | sig_mime | sig_desc |
|---|---|---|
| apps/renamed_archive.apk | application/zip | 일반 ZIP(내부 구조로 확인하는 형식 아님) |
| docs/meeting_notes.txt | text/plain | 텍스트(utf-8) / 중간·끝 구간에 텍스트가 아닌 데이터 |
| docs/secret.txt | application/octet-stream | 알 수 없는 바이너리 |
| images/mismatch_signature.jpg | image/png | PNG image data, 1 x 1, 8-bit/color RGBA |

**인코딩별 검색** (`search --kw 비밀번호 --kw error`)

| 파일 | 줄 | 일치 | 인코딩 |
|---|---|---|---|
| docs/memo_cp949.txt | 2 | 비밀번호 | cp949 |
| docs/memo_utf16.txt | 2 | 비밀번호 | utf-16 |
| logs/app.log | 2 | ERROR | utf-8 |

**앱 패키지** (`apps`) — 더미 APK는 테스트용으로 컴파일된 매니페스트를 직접 만들어 넣었다. 표에서는 권한 앞의 `android.permission.`을 생략했다

| rel_path | package | version_name | permissions | status |
|---|---|---|---|---|
| apps/backup.zip | com.example.tracker | 0.9 | ACCESS_FINE_LOCATION; RECEIVE_BOOT_COMPLETED | ok |
| apps/renamed_archive.apk | | | | not_app |
| apps/sample.ipa | org.example.photos | 2.1 | NSCameraUsageDescription; NSPhotoLibraryUsageDescription | ok |
| apps/structured_sample.apk | org.example.notes | 1.2.0 | INTERNET; READ_CONTACTS | ok |

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
| `test_signature.py` | 잡아야 하는 위장 / 잡으면 안 되는 정상 파일(APK·IPA·문서의 ZIP 내부 구조 포함), 읽기 실패 처리, 판정 규칙 |
| `test_inventory_hashing.py` | 정렬·상대 경로, 심볼릭 링크 정책, 순환 링크, OS별 시간 필드, 해시 상태 |
| `test_search_timeline.py` | 인코딩별 검색, 줄마다 인코딩이 다른 로그(무작위로 섞은 파일 40개를 원문과 비교), 잘린·깨진 파일 검색, 줄 번호, 건너뛴 파일 기록, 수상한 시각 |
| `test_validate.py` | 변조·이동·삭제 판정, 해시 없는 기준본, NFD 파일명, CSV 수식 주입 왕복 |
| `test_artifactdiff.py` | WAL에만 있는 행 탐지, 원본 무변경, `-wal`만 바뀐 경우, WITHOUT ROWID 테이블, 설정 XML·plist 키 비교, 깨진 파일 |
| `test_appinfo.py` | APK·IPA 정보 추출, `.zip`으로 둔 앱, 분석 방해 ZIP 조작이 있는 APK, 깨진 plist, androguard가 없을 때 |
| `test_cli.py` | 잘못된 입력 사전 차단, 결과 폴더 자동 제외, 스캔 옵션 비교, 더미 데이터 전체 결과 |

## 6. 구조

```
main.py                      명령줄 진입점(입력 사전 검사)
forensic_analyzer/
  inventory.py               폴더 순회, 메타데이터, 심볼릭 링크 정책
  hashing.py                 해시 계산과 상태
  signature.py               매직 넘버·libmagic 판별, 확장자 위장 판정
  container.py               ZIP 내부 구조로 APK·IPA·DOCX·HWPX 등 판별
  textutil.py                텍스트·인코딩 판별(시그니처와 검색이 공용)
  search.py                  키워드 검색
  timeline.py                타임라인
  validate.py                검증, 기준본 비교
  appinfo.py                 앱 패키지(APK·IPA) 정보·권한 추출
  artifactdiff.py            앱 행동 전후 수집본 비교(SQLite 행, 설정 키)
  foroutput.py               CSV 저장(원자적 저장, 수식 주입 방지)
  dummy_test.py              테스트용 더미 증거 생성
tests/                       pytest
samples/fossify_notes/       실제 앱(에뮬레이터) 행동별 수집본
docs/                        트러블슈팅, 앱 아티팩트 명세
```

## 7. 한계

1. 파일 시스템 수준 분석이 아니므로 삭제된 파일 복구, NTFS 대체 데이터 스트림(ADS) 목록화는 하지 않는다.
2. PDF·Word 본문 검색은 지원하지 않는다.
3. 시각 조작은 명백한 경우(0 이하·미래)만 표시한다. 그럴듯한 과거 시각으로 바꾼 조작은 파일 시스템 메타데이터 비교(예: NTFS `$STANDARD_INFORMATION`과 `$FILE_NAME`)가 필요하다.
4. 분석 대상을 직접 읽으므로 접근 시각(atime)이 바뀔 수 있다. 원본이 아닌 사본이나 읽기 전용 마운트에서 실행해야 한다.
5. 256바이트 미만 파일은 무작위 데이터가 우연히 텍스트 조건을 통과할 수 있어 텍스트 판별 신뢰도가 낮다.
6. GBK 중국어 문서는 CP949로도 디코딩되고 둘을 가려낼 근거가 없어 자동 구분이 안 된다. 검색하려면 `--encodings utf-8 gbk`처럼 지정해야 한다. 한 파일 안에 레거시 인코딩이 두 종류 이상 섞인 경우(예: CP949 줄과 Shift-JIS 줄)도 대표 인코딩 하나만 우선하므로 일부 줄이 잘못 읽힐 수 있다.
7. 텍스트 뒤 은닉 탐지는 앞·중간·끝 8KB씩 표본을 본다. 표본 사이에 숨긴 작은 데이터는 놓칠 수 있다.
8. libmagic 버전에 따라 세부 MIME 이름이 다를 수 있다. 허용 표에 없는 MIME이면 내장 판별 결과로 판정한다.
9. 대부분의 Linux에서는 생성 시각을 제공하지 않아 `birthtime_epoch`가 비어 있다.
10. 확장자 위장 판정은 허용 확장자 목록 방식이라, 도구가 모르는 확장자로 위장한 파일(예: PNG를 `.xyz`로)은 "판정 불가"로 두고 잡지 않는다.
11. 시그니처 판별은 파일 앞부분을 인코딩 하나로 판정하므로, UTF-8 줄과 CP949 줄이 뒤섞인 로그는 "알 수 없는 바이너리"로 보고 확장자 불일치 경고를 낼 수 있다. 검색은 줄 단위로 읽으므로 이런 파일에서도 키워드를 정상적으로 찾는다.
12. ZIP 내부 구조 확인은 패키지 구조 수준이다. APK 서명 검증이나 코드(DEX) 디컴파일은 하지 않는다. 문서(DOCX 등)는 필수 파일 이름까지만 보므로, 이름을 맞춰 일부러 만든 ZIP은 통과할 수 있다. AAB·XAPK·JAR 등 그 밖의 ZIP 계열은 내부 구조를 확인하지 않고 ZIP 계열 확장자로만 허용한다.
13. 앱 정보는 패키지에 적힌 값을 읽는 수준이다. APK 서명은 있는지(방식)만 보고 인증서를 검증하지 않으며, 코드 디컴파일·동적 분석은 하지 않는다. App Store에서 받은 IPA의 실행 파일 암호화(FairPlay) 여부도 확인하지 않는다. 앱 이름이 리소스 참조인데 리소스가 조작되면 `app_name`이 비어 있을 수 있다. 압축 안의 압축에 든 앱(XAPK·APKS 묶음, ZIP 안의 APK)은 찾지 않는다. androguard는 APK 전체를 메모리에 올리므로 수 GB 크기의 APK는 메모리를 많이 쓴다.
14. `appdiff`는 DB의 **현재 상태**끼리 비교한다. 삭제된 레코드가 남아 있는 빈 페이지나 WAL의 이전 프레임은 복구하지 않는다. 행을 rowid로 짝지으므로, 삭제 후 같은 rowid로 다시 넣은 행은 "변경"으로 보인다. SQLite·설정 XML·plist가 아닌 형식(예: DataStore의 protobuf)은 파일 단위 변화만 보여 준다. DB 내용을 모두 메모리에 올려 비교하므로 수 GB짜리 DB는 메모리를 많이 쓴다. 심볼릭 링크는 비교하지 않는다. UTF-8로 읽히지 않는 글자는 대체 문자로 바꿔 비교하므로 깨진 바이트끼리만 다른 변경은 놓친다. `--with-hash`·`--with-signature` 등 공통 옵션은 `appdiff`에서 쓰지 않는다(파일 비교에는 항상 SHA-256을 쓴다).

## 8. 향후 보완점

1. 다른 앱(메신저·브라우저 등)으로 아티팩트 명세 확대
2. 이미지(EXIF)·문서 내부 상세 분석
3. 디스크 이미지(E01, dd) 직접 분석
4. 검색 인덱스로 대용량 검색 속도 향상
5. SQLite 삭제 레코드(빈 페이지·WAL 이전 프레임) 복구

### 관련 학습 내용 정리

- https://velog.io/@ahrdyrxkddhfl/파일-시스템
