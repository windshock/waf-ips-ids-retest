# Target Profile Schema

Store reusable target facts separately from the run configuration.

## Required fields

- `name`: short profile name
- `domains`: list of target domains
- `environment_mode`: `A`, `B`, or `C` if already known, otherwise omit and let the run manifest record it
- `http_visibility`: whether HTTP or plaintext traffic exists
- `critical_endpoints`: endpoints used for core TCs
- `encrypted_endpoints`: endpoints that require a real encryptor
- `approval_levels`: high-risk gating notes
- `tc_scope`: which TCs are in scope

## Recommended fields

- `protocol_notes`
- `soc_contact`
- `timezone`
- `marker_prefix`
- `known_parsers`
- `known_proxy_chain`
- `capabilities`: protocol features and whether they are `present`, `absent`, or `unknown`
- `cacheable_paths`
- `routing_headers`
- `cookie_sensitive_paths`
- `scheme_pairs`: optional explicit `http://` and `https://` pairs for timeout and parity comparison
- `request_contracts`: optional list of reusable captured request-contract files for contract-aware mutation families

## Example

```yaml
name: example-web-api
domains:
  - api.example.com
  - auth.example.com
http_visibility:
  available: false
critical_endpoints:
  plaintext_json:
    - https://api.example.com/v1/health
  auth_like:
    - https://auth.example.com/login
encrypted_endpoints:
  required: true
  notes: "Real app-side encryptor required for visibility testing"
approval_levels:
  high_risk:
    - TC-07
    - TC-08
    - TC-09
    - TC-16
capabilities:
  http3: unknown
  websocket: absent
  graphql: unknown
  grpc: absent
cacheable_paths:
  - https://api.example.com/v1/public
scheme_pairs:
  - https: https://api.example.com/v1/health
    http: http://api.example.com/v1/health
    note: "Compare plaintext and TLS behavior before attributing timeouts to IPS"
request_contracts:
  - path: ./request_contract.example.json
    endpoint: https://api.example.com/v1/read
    target_path: ReqData.ReqBody
    notes: "Use contract-aware TC-12/15/21/22/23 mutations here"
routing_headers:
  - Host
  - X-Forwarded-Host
  - Forwarded
tc_scope:
  core:
    - TC-01
    - TC-03
    - TC-08
    - TC-10
    - TC-11
    - TC-12
    - TC-15
    - TC-17
    - TC-18
    - TC-19
    - TC-20
    - TC-21
    - TC-22
    - TC-23
    - TC-24
  conditional:
    - TC-25
    - TC-26
```
