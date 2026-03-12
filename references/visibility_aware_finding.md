# Visibility-Aware Finding Attribution

## 목적

이 문서는 "IPS/WAF가 X를 탐지한다" 또는 "X로 IPS/WAF를 우회한다"는 종류의 finding을 작성할 때, **어떤 transport에서 테스트했는지**와 **해당 transport에서 보안장비가 트래픽을 볼 수 있는지**를 반드시 명시하도록 강제한다.

## 핵심 규칙

### 규칙 1: 우회(bypass) 주장에는 가시(visible) 경로 증거가 필수

"보안장비가 X를 탐지하지 못한다" 또는 "X 기법으로 보안장비를 우회할 수 있다"는 finding은, **보안장비가 트래픽을 볼 수 있는 경로**(IPS-visible path)에서 테스트한 증거가 있어야만 작성할 수 있다.

- Mode B(HTTPS 비가시)에서 HTTPS로만 테스트한 결과로는 우회 주장 불가
- HTTPS에서 통과되었다면 해석은 `visibility-limited`이지 `control-gap`이 아님
- 우회 주장을 하려면 IPS-visible 경로(plaintext HTTP 등)에서 같은 기법을 재현해야 함

### 규칙 2: 4-cell 검증 매트릭스

우회 여부를 주장하려면 최소 4가지 조합을 IPS-visible 경로에서 테스트해야 한다:

```
                  | 기법 미적용       | 기법 적용
    ──────────────┼──────────────────┼──────────────────
    정상 payload  | baseline         | 기법 단독 영향
    공격 payload  | 탐지 확인(대조군) | 우회 여부(핵심)
```

예시 — TC-18 압축 우회 검증:

| | 비압축 | gzip |
|---|---|---|
| benign body | 302 (baseline) | 302 (압축 자체는 통과) |
| JNDI body | timeout (IPS 탐지) | **302 (우회 확인)** |

4-cell 중 하나라도 빠지면 finding에 "(불완전 검증)"을 표기한다.

### 규칙 3: 모든 finding에 transport 속성 필수

finding을 작성할 때 다음 3개 속성을 반드시 명시한다:

| 속성 | 값 | 설명 |
|---|---|---|
| `tested_transport` | `HTTP` / `HTTPS` / `HTTP/2` / `both` | 어떤 transport에서 테스트했는가 |
| `ips_visible` | `yes` / `no` / `partial` | 해당 transport에서 IPS가 트래픽 내용을 볼 수 있는가 |
| `attribution` | 아래 참조 | finding의 근본 원인 |

attribution 값:

- `ips-bypass`: IPS가 볼 수 있는데도 탐지 실패 (가시 경로에서 확인)
- `ips-non-visible`: IPS가 못 보는 경로라서 통과 (우회가 아님)
- `proxy-config`: 프록시/LB 설정 문제 (IPS와 무관)
- `app-level`: 앱 서버 자체의 입력 검증 문제
- `mixed`: 복합 원인

### 규칙 4: HTTPS-only finding의 해석 제한

Mode B에서 HTTPS로만 테스트한 finding은:

- `ids_status`를 `missed` 또는 `control-gap`으로 쓸 수 없음
- `visibility-limited`만 사용 가능
- "앞단에서 차단하지 않음"이라고 쓸 수 없음 → "HTTPS 비가시 영역에서 앱까지 도달함"으로 써야 함
- 보고서의 조치에 "SSL 가시성 확보"를 최우선으로 기재해야 함

## TC별 가시 경로 테스트 요구사항

다음 TC는 우회 주장 시 반드시 IPS-visible 경로 테스트가 필요하다:

| TC | 우회 주장 조건 | 필수 IPS-visible 테스트 |
|---|---|---|
| TC-08 | split-packet이 IPS를 우회한다 | plaintext HTTP에서 split-packet 재현 |
| TC-12 | oversize body가 IPS를 우회한다 | plaintext HTTP에서 oversize body 전송 |
| TC-15 | malformed JSON이 IPS를 우회한다 | plaintext HTTP에서 malformed JSON + 공격 payload |
| TC-18 | 압축 body가 IPS를 우회한다 | **plaintext HTTP에서 4-cell 매트릭스** |
| TC-23 | charset 변환이 IPS를 우회한다 | plaintext HTTP에서 charset 변환 + 공격 payload |

## 보고서 작성 예시

❌ 잘못된 작성:
> 압축된 요청 body가 앞단 검사 없이 앱까지 도달함

✅ 올바른 작성 (HTTPS-only인 경우):
> 압축된 요청 body가 앱까지 도달함 (HTTPS 비가시 영역, IPS 검사 대상 아님)

✅ 올바른 작성 (HTTP에서 확인한 경우):
> 압축된 요청 body가 IPS 검사를 우회함 (plaintext HTTP에서 4-cell 검증 완료: 비압축 JNDI body는 timeout, gzip JNDI body는 302)
