# OCB Example Profile

Use this as an example profile, not as a hardcoded default.

```yaml
target:
  name: "okcashbag"
  domains:
    - "www.okcashbag.com"
    - "member.okcashbag.com"
    - "msg.okcashbag.com"
  http_visible_domains:
    - "msg.okcashbag.com"
  https_visibility_mode: "unknown"
  critical_endpoints:
    - "https://msg.okcashbag.com/sugar/app/extra_meta"
    - "https://msg.okcashbag.com/sugar/home/v4/blocks"
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
    - "https://www.okcashbag.com/"
  encrypted_endpoints:
    - endpoint: "https://msg.okcashbag.com/sugar/auth/login"
      mode: "crypted=1"
    - endpoint: "https://msg.okcashbag.com/sugar/point/summary"
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
  marker_prefix: "OCB-SECURITY-AUDIT"
  timezone: "Asia/Seoul"
  use_sudo: true
  ssl_mirror_confirmed: false
  https_monitored: false
  run_high_risk: true
```
