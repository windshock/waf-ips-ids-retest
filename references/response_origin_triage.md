# Response Origin Triage

Use this reference when repeated `4xx/5xx`, timeout, or reset behavior must be attributed conservatively.

## Goal

Do not stop at `403`, `401`, `500`, or `timeout`. Decide whether the visible behavior most likely came from:

- `front-nginx-likely`
- `edge-waf-likely`
- `upstream-app-likely`
- `upstream-spring-likely`
- `upstream-tomcat-likely`
- `network-drop-or-hold`
- `unknown`

## Minimum Signals

- status line
- `Server` header when present
- `Content-Type`
- body fingerprint or exact repeated body
- whether the same page repeats across unrelated TCs
- whether the request got a real HTTP response vs timeout/reset/no-response

## Practical Heuristics

### Front proxy or shared nginx error page

Treat repeated responses as `front-nginx-likely` when most of these are true:

- `Server: nginx`
- identical `Content-Length` or `ETag` across unrelated test cases
- same HTML body repeats for Unicode, oversize, segmentation, and baseline-deny cases
- body looks like a static site error page rather than structured application JSON

### Edge WAF or CDN generated

Treat as `edge-waf-likely` when:

- headers expose CDN or WAF markers such as Cloudflare, Akamai, Imperva, Incapsula, AWS edge, or similar
- block pages include vendor-branded wording or request IDs
- responses differ from the application's normal HTML or JSON style but remain consistent at the edge

### Upstream application generated

Treat as `upstream-app-likely` when:

- body is structured JSON with app-specific fields such as `code`, `message`, `detailMessage`
- `Content-Type` is any JSON-like variant, including `application/json` or `text/json`
- error semantics differ by endpoint or contract instead of collapsing to one shared page
- body changes with business logic inputs while headers stay stable

### Spring-generated

Treat as `upstream-spring-likely` when:

- body matches Spring Boot default JSON error fields such as `timestamp`, `status`, `error`, `path`
- `Whitelabel Error Page` appears
- stack traces or Spring exception names appear

### Tomcat-generated

Treat as `upstream-tomcat-likely` when:

- body matches Tomcat error report HTML
- strings such as `Apache Tomcat`, `HTTP Status 403`, or `type Status report` appear

### Network drop, inline hold, or silent control

Treat as `network-drop-or-hold` when:

- there is no HTTP response body
- the request times out repeatedly
- raw or segmented traffic gets ACKed or partially ACKed but no completed HTTP response appears

## Conservative Rule

- A `403` alone is never enough to call the owner `IPS`
- `Server: nginx` alone is not enough to exclude upstream involvement
- If a reverse proxy may intercept upstream errors, prefer `front-nginx-likely` over naming Tomcat or Spring directly unless the body proves it

## Docker fallback

If ownership is still ambiguous, run the local Docker lab:

- bring it up with `scripts/docker_response_origin_lab.sh up`
- collect sample responses with `scripts/docker_response_origin_lab.sh probe <output_dir>`
- compare saved target artifacts with the lab outputs using `scripts/classify_response_origin.py`

The lab provides:

- static nginx error page
- proxy-pass and proxy-intercept patterns
- Spring-style JSON error response
- Tomcat-style HTML error response
- app-specific JSON error response
- hold/no-response pattern
