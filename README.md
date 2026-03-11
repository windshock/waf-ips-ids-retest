# waf-ips-ids-retest

Evidence-first retest framework for WAF, IPS, and IDS validation with SOC handoff.

This repository is a Codex local skill. The skill entrypoint is [`SKILL.md`](./SKILL.md).

## Included

- readiness and environment classification workflow
- evidence model and SOC handoff templates
- response-origin triage guidance
- Suricata inline comparison lab
- probe runners for TC-08 and TC-17 through TC-24

## Use

Copy this folder into your local Codex skills directory as `waf-ips-ids-retest`, then trigger it with:

```text
$waf-ips-ids-retest
```

## Validate

If you have Codex skill tooling available, validate the skill with the standard validator for your environment.
