# Response Origin Triage

Use this reference when repeated `4xx/5xx`, timeout, or reset behavior must be attributed conservatively.

## Goal

Do not stop at `403`, `401`, `500`, or `timeout`. Decide whether the visible behavior most likely came from:

- `front-nginx-likely`
- `front-web-likely`
- `edge-waf-likely`
- `upstream-app-likely`
- `upstream-nextjs-likely`
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

### Front web redirect or short `400`

Treat as `front-web-likely` when:

- the response is `301/302/307/308` with an explicit `Location`
- or the response is a short `400` body such as `Not Found(400)`
- and the body does not look like app JSON, Next.js HTML, Spring JSON, or Tomcat markup

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

### Next.js generated

Treat as `upstream-nextjs-likely` when:

- the body contains `__next_f.push`, `/_next/static/`, or similar Next.js markers
- route-specific and generic shell documents differ while status may remain `200`
- the behavior looks like route resolution or fallback rather than an edge-generated error page

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
- A `302` redirect is often a web-tier behavior, not an IPS signal
- A short `400` body may come from the front web tier even when the `Server` header is hidden

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
- and you should add target-shaped patterns such as redirects, short `400` pages, route-shell fallback documents, or service-specific JSON envelopes before writing the final report
