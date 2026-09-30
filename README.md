# 💚ForensicFileAnalyzer : 포렌식 툴 만들기

## 1. 목적

파일 해시값 계산(MD5, SHA-256), 파일 시그니처 확인(매직 넘버로 실제 파일 타입 판별), 메타데이터 추출(생성/수정 시간 등), .csv 형태로 결과 저장, 간단한 키워드 검색 기능(문서 파일 내 특정 단어 찾기) 기능을 포함한 파일 분석 도구 개발을 목적으로 한다.

## 2. 프로그램 개발

### ① 파일 인벤토리 & 메타데이터 추출

1. 파일 이름, 위치(경로), 크기, 만든 시간, 수정 시간 등의 기본 정보를 추출함.
2. 결과물은 표(CSV) 파일로 정리

### ② 해시 계산 (MD5 + SHA-256)

1. 각 파일의 고유값을 만듦. 파일이 나중에 바뀌었는지, 복사본이 같은지 확인할 수 있다.
2. 결과물은 위의 표(CSV)에 MD5, SHA-256열이 추가된 형태.

### ③ 파일 시그니처 확인(libmagic)

1. 확장자(.jpg, .pdf)가 아니라 실제 데이터를 보고 파일 종류를 확인한다.
   - libmagic(python-magic)이 있으면 libmagic으로 판별하고, 없으면 직접 정의한 매직 넘버 표(PNG, JPEG, GIF, PDF, ZIP, SQLite, OLE, 바이너리 plist, GZIP)로 판별한다.
   - 어느 경우에도 확장자로 형식을 추측하지 않는다. 확장자로 추측하면 확장자 위장을 탐지할 수 없기 때문이다.
   - APK·DOCX·HWPX처럼 내부가 ZIP인 형식, HWP·DOC처럼 내부가 OLE인 형식, .log·.py처럼 내용이 일반 텍스트인 형식은 불일치로 보지 않는다.
   - 내용을 알 수 없는 바이너리일 때는 확장자에 따라 다르게 판단한다.
     - .png·.pdf·.zip·.hwp처럼 시그니처가 반드시 있어야 하는 확장자면 불일치(헤더 훼손·위장 의심).
     - .txt·.log 같은 텍스트 확장자면 **엔트로피**(바이트가 얼마나 무작위한지, 0~8)로 판단한다. 실측 결과 정상 텍스트(latin-1, Shift-JIS, BOM 없는 UTF-16, NUL로 채워진 로그)는 2.4~4.3, 무작위·암호화 데이터는 7.9 이상이어서 7.0 이상일 때만 불일치로 본다(암호화 파일 은닉 의심). 테스트 데이터의 `docs/secret.txt`가 이 경우다.
     - .bin·.dat처럼 원래 아무 바이너리나 담는 확장자는 판단하지 않는다.
   - BOM(`FF FE` 등)으로 시작해도 실제로 그 인코딩으로 디코딩되고 엔트로피가 낮을 때만 텍스트로 인정한다. 무작위 바이트 앞에 BOM 2바이트만 붙여 판정을 피하는 것을 막기 위함이다.
   - Windows 썸네일 캐시 `Thumbs.db`처럼 OLE 형식인 .db 파일도 정상으로 본다.
2. 결과물에 실제 파일 타입을 기록하는 열과, 확장자와 맞는지 여부를 체크하는 열이 추가됨.

### ④ 키워드 검색(경량 텍스트 대상)

1. 텍스트 파일(txt, csv, 로그파일 등) 안에서 특정 단어를 찾는다.
2. 검색에 걸린 파일 목록과 줄 번호를 별도의 CSV에 저장한다.
   - BOM이 있으면 UTF-8/16/32로, 없으면 UTF-8 → CP949 → latin-1 순서로 디코딩한다. 메모장의 ANSI(CP949)·유니코드(UTF-16) 저장 문서도 검색되며, 실제로 사용한 인코딩을 결과에 기록한다.
3. 처음엔 가벼운 텍스트만 검색, 나중에 PDF, word 파일 등도 대상으로 버전 업데이트.

### ⑤ 타임라인 뷰(경량)

1. 모든 파일의 시간 정보를 시간 순서대로 정렬한다.
2. 결과물은 시간 순으로 정리된 CSV.

### ⑥ 품질/검증

1. 해시값 계산, CSV 내 누락 및 오류 확인. 샘플 데이터를 돌려서 비교 검증.
   - `--baseline`: 예전에 저장한 인벤토리 CSV(기준본)와 현재 상태를 비교해 삭제(BASELINE_MISSING), 추가(BASELINE_NEW), 이동(MOVED, 해시는 같고 경로만 바뀜), 내용 변경(HASH_CHANGED), 크기·수정 시각 변경을 기록한다. 파일은 루트 기준 상대 경로(rel_path)로 짝지으므로 증거 폴더를 옮겨도 비교할 수 있다.
   - 크기와 수정 시각까지 원래대로 맞춘 변조도 해시로 잡아낸다. 반대로 기준본과 공통 해시 열이 없으면 내용 검증을 못 한 것이므로 BASELINE_NO_HASH를 WARN으로 남긴다.
   - 인벤토리 CSV가 아닌 파일을 기준본으로 주거나, 출력 길이를 따로 지정해야 하는 해시(shake_128 등)를 주면 스캔 전에 오류로 종료한다. 해시 이름은 소문자로 통일한다.
   - `--verify-hash`: 같은 실행 안에서 일부 파일의 해시를 다시 계산해 계산 일관성을 확인한다. 시간이 지난 뒤의 변경 탐지는 `--baseline`이 담당한다.
2. 신뢰성 확보 담기.

## 3. 설치 및 실행

```bash
pip install -r requirements.txt
python forensic_analyzer/dummy_test.py          # 테스트용 더미 증거 생성

python main.py inventory ForensicTestData --with-hash --with-signature
python main.py search    ForensicTestData --kw error --kw 비밀번호
python main.py timeline  ForensicTestData --tz-offset-min 540      # KST
python main.py validate  ForensicTestData --with-hash --verify-hash --with-signature

# 변경 탐지: 수집 시점의 인벤토리를 기준본으로 저장해 두고, 나중에 비교
python main.py inventory ForensicTestData --with-hash --out outputs/baseline.csv
python main.py validate  ForensicTestData --baseline outputs/baseline.csv
```

결과 CSV는 `outputs/` 폴더에 `<명령>_<라벨>_<시각>.csv` 형태로 저장된다.

## 4. 결과

### ① 실행
#### 더미 데이터 생성
dummy_test.py 실행 > ForensicTestData 폴더 생성 후, 안에 더미 테스트 파일들 같이 생성된 것 확인
- <img width="224" height="203" alt="image" src="https://github.com/user-attachments/assets/a8417227-27cd-4a18-a0b4-d41337fa18ee" />

#### .csv 형태로 저장

- 터미널 명령어
<img width="586" height="143" alt="image" src="https://github.com/user-attachments/assets/4e06e6a6-fd38-4a5d-9c44-05276fe46e39" />

- outputs 결과
<img width="242" height="397" alt="image" src="https://github.com/user-attachments/assets/af66cfb4-6b06-442c-81da-5616e13021e0" />


.CSV 형태로 잘 생성되었다. 여러번 실행해도 타임스탬프가 찍혀 나오기 때문에 헷갈릴 일은 없다.

실행하면 아래와 같이 내용을 확인할 수 있다
<img width="663" height="105" alt="image" src="https://github.com/user-attachments/assets/be50a223-a6c5-4e71-a43f-7a7c1a7dbb95" />


### ② 한계

1. 지워진 파일 복구 미지원
2. PDF, word 문서 등 검색 기능 미지원
3. 공격자에 의한 시간 정보 조작 가능성
4. 분석 대상을 직접 읽으므로 접근 시간(atime)이 바뀔 수 있음 — 원본이 아닌 사본이나 읽기 전용 마운트에서 실행해야 함
5. 심볼릭 링크: 기본 모드에서는 목록에서 제외되고, `--follow-symlinks` 모드에서는 순환 링크 방지 로직이 없음 (테스트 데이터의 `symlinks/link_to_report.txt`는 Windows에서 생성되어 실제 링크가 아닌 일반 파일임)
6. 검색: 10MB 초과 파일은 건너뛰며 건너뛴 목록을 따로 기록하지 않음, 한 줄에 같은 키워드가 여러 번 나와도 1건으로 기록함, 한국어·UTF 위주라 Shift-JIS 일본어·GBK 중국어·BOM 없는 UTF-16 문서는 검색되지 않음
7. 타임라인: Windows에서는 ctime이 생성 시각인데 MetadataChanged로 표시됨
8. 시그니처 허용 확장자 일부를 OS의 mimetypes 설정에 의존하므로 PC마다 결과가 약간 다를 수 있음
9. 엔트로피 판단은 256바이트 이상일 때만 하므로, 그보다 작은 암호화 파일이 텍스트 확장자로 숨어 있으면 놓칠 수 있음. 또 압축 파일 등 원래 엔트로피가 높은 정상 파일에 .txt를 붙인 경우도 불일치로 표시됨(의도된 동작)

### ③ 향후 보완점

1. 이미지 파일, 문서 파일, 압축 파일 등 상세 분석 추가
2. 디스크 전체 복제본(이미지 파일) 분석도 지원
3. 검색 속도 향상을 위해 인덱스 추가


### 관련 학습 내용 정리

- https://velog.io/@ahrdyrxkddhfl/파일-시스템
