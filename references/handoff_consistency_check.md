# Handoff Consistency Check

## 목적

SOC handoff 전에 산출물 간 정합성을 자동 검증하여, 중복·누락·불일치를 잡는다.

## 검증 항목

### 1. SOC Handoff Key Findings 중복 검사

`soc_handoff.md`의 Key Findings 항목이 중복되면 안 된다.

검증 방법:
```bash
grep "^- " artifacts/soc_handoff.md | sort | uniq -d
```
빈 출력이면 통과. 중복 행이 나오면 제거한다.

### 2. CSV 행 수 ↔ SOC Handoff Row Count 일치

`soc_handoff.md`에 기재된 Row Count와 `combined_evidence.csv`의 실제 데이터 행 수가 일치해야 한다.

검증 방법:
```bash
CSV_ROWS=$(($(wc -l < artifacts/combined_evidence.csv) - 1))
CLAIMED=$(grep "Row Count:" artifacts/soc_handoff.md | grep -o '[0-9]*')
[ "$CSV_ROWS" -eq "$CLAIMED" ] && echo "PASS" || echo "FAIL: CSV=$CSV_ROWS, claimed=$CLAIMED"
```

### 3. Query Windows가 모든 timestamp를 포함

`soc_handoff.md`의 Query Windows 시간 범위가 CSV의 모든 timestamp를 포함해야 한다.

검증 방법:
```python
import csv
from collections import defaultdict
rows = defaultdict(list)
with open('artifacts/combined_evidence.csv') as f:
    for r in csv.DictReader(f):
        rows[r['protocol']].append(r['timestamp'])
for proto in sorted(rows.keys()):
    ts = sorted(rows[proto])
    print(f'{proto}: {ts[0]} ~ {ts[-1]} ({len(ts)} rows)')
```
출력을 soc_handoff.md의 Query Windows와 비교한다.

### 4. Coverage Matrix 완결성

`coverage_matrix.md`에 다음이 모두 포함되어야 한다:

- TC-01 ~ TC-26 (전체 TC 목록)
- CSV에 나타나는 모든 비-TC 카테고리 (BODY-DETECTION, SCHEME-PARITY 등)

검증 방법:
```bash
# CSV의 tc 컬럼에서 고유값 추출
awk -F',' 'NR>1 {print $3}' artifacts/combined_evidence.csv | sort -u

# coverage_matrix.md에서 TC/helper 목록 추출하여 비교
```

### 5. Finding의 transport attribution 존재

`execution_summary.json`의 모든 finding에 어떤 transport(HTTP/HTTPS/both)에서 관측되었는지 명시되어 있는지 확인한다.

### 6. soc_handoff_meta.json ↔ soc_handoff.md 동기화

`soc_handoff_meta.json`의 `high_level_findings` 개수와 `soc_handoff.md`의 Key Findings bullet 개수가 일치해야 한다.

검증 방법:
```bash
META_COUNT=$(python3 -c "import json; print(len(json.load(open('artifacts/soc_handoff_meta.json'))['high_level_findings']))")
HANDOFF_COUNT=$(grep -c "^- " artifacts/soc_handoff.md)
echo "meta=$META_COUNT handoff=$HANDOFF_COUNT"
```

## 실행 시점

이 검증은 **Phase 6 (SOC Handoff)** 렌더링 직후, 보고서를 최종 확정하기 전에 반드시 실행한다.

## 자동화

향후 `scripts/validate_handoff_consistency.py`로 통합하여, `render_soc_handoff.py` 실행 후 자동 호출되도록 한다.
