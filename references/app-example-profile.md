# Mobile App Example Profile

Use this as an example profile, not as a hardcoded default.

```yaml
target:
  name: "example-mobile-app"
  domains:
    - "www.example-app.test"
    - "member.example-app.test"
    - "api.example-app.test"
  http_visible_domains:
    - "api.example-app.test"
  https_visibility_mode: "unknown"
  critical_endpoints:
    - "https://api.example-app.test/api/meta"
    - "https://api.example-app.test/api/home/blocks"
  capabilities:
    http3: "unknown"
    websocket: "absent"
    graphql: "absent"
    grpc: "absent"
  routing_headers:
    - "Host"
    - "X-Forwarded-Host"
    - "Forwarded"
  cacheable_paths:
    - "https://www.example-app.test/"
  encrypted_endpoints:
    - endpoint: "https://api.example-app.test/api/auth/login"
      mode: "crypted=1"
    - endpoint: "https://api.example-app.test/api/points/summary"
      mode: "crypted=2"
  approval_levels:
    tc07: "high"
    tc08: "high"
    tc09: "high"
    tc16: "high"
  tc_scope:
    reproduce:
      - "TC-01"
      - "TC-03"
      - "TC-10"
      - "TC-11"
      - "TC-12"
    extend:
      - "TC-07"
      - "TC-08"
      - "TC-09"
      - "TC-15"
      - "TC-16"
      - "TC-17"
      - "TC-18"
      - "TC-19"
      - "TC-20"
      - "TC-21"
      - "TC-22"
      - "TC-23"
      - "TC-24"
    conditional:
      - "TC-25"
      - "TC-26"

run_config:
  callback_domain: "replace-me.oast.site"
  tester_ip: "replace-me"
  results_dir: "./test_results"
  marker_prefix: "APP-SECURITY-AUDIT"
  timezone: "Asia/Seoul"
  use_sudo: true
  ssl_mirror_confirmed: false
  https_monitored: false
  run_high_risk: true
```
