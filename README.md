# waf-ips-ids-retest

Evidence-first retest framework for WAF, IPS, and IDS validation with SOC handoff.

This repository is a Codex local skill. The skill entrypoint is [`SKILL.md`](./SKILL.md).

## Full Article

- https://windshock.github.io/en/post/2026-03-13-waf-ips-ids-detection-gap-analysis/

## Included

- readiness and environment classification workflow
- hypothesis-driven interpretation rules that separate facts, premises, hypotheses, and conclusions
- evidence model and SOC handoff templates
- response-origin triage guidance
- Suricata inline comparison lab
- sample Docker origin lab for response-family, parser, and proxy-shape calibration
- probe runners for TC-08 and TC-17 through TC-24, including dedicated TC-24 smuggling and multi-client fan-out probes

## Release Notes

- See [CHANGELOG.md](./CHANGELOG.md) for TC-24 smuggling, multi-client fan-out, hypothesis/experiment workflow updates, and Docker lab fixes.
- See [references/tc24_reference_notes.md](./references/tc24_reference_notes.md) for the external references used to shape the TC-24 runners and interpretation rules.

## Related Skills

- For the shared hypothesis / experiment workflow that sits above this skill, see [`security-hypothesis-lab`](https://github.com/windshock/security-hypothesis-lab).

## Use

Copy this folder into your local Codex skills directory as `waf-ips-ids-retest`, then trigger it with:

```text
$waf-ips-ids-retest
```

## Validate

If you have Codex skill tooling available, validate the skill with the standard validator for your environment.
