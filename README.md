# waf-ips-ids-retest

Evidence-first retest framework for WAF, IPS, and IDS validation with SOC handoff.

This repository ships as a skill for AI coding assistants. The entrypoint is [`SKILL.md`](./SKILL.md), whose frontmatter is consumed by both Claude Code and Codex.

## Full Article

- https://windshock.github.io/en/post/2026-03-13-waf-ips-ids-detection-gap-analysis/

## Included

- readiness and environment classification workflow
- hypothesis-driven interpretation rules that separate facts, premises, hypotheses, and conclusions
- evidence model and SOC handoff templates
- response-origin triage guidance
- Suricata inline comparison lab
- sample Docker origin lab for response-family, parser, and proxy-shape calibration
- white-box Coraza WAF lab for TC-27 multipart grammar differentials
- probe runners for TC-08 and TC-17 through TC-24, including dedicated TC-24 smuggling and multi-client fan-out probes

## Requirements

- Docker / Docker Compose — for the white-box labs under `assets/` (Coraza WAF, Suricata inline, sample origin, multipart parser, response origin)
- Python 3.10+ — for the probe runners under `scripts/`
- See [`references/dependencies.md`](./references/dependencies.md) for per-test details

## Install

### Claude Code

Copy the repository contents into your skills directory under the name `waf-ips-ids-retest`:

```bash
# Project-scoped
mkdir -p .claude/skills/waf-ips-ids-retest
cp -R /path/to/this/repo/. .claude/skills/waf-ips-ids-retest/

# Or user-scoped (available across projects)
mkdir -p ~/.claude/skills/waf-ips-ids-retest
cp -R /path/to/this/repo/. ~/.claude/skills/waf-ips-ids-retest/
```

Claude auto-triggers from the description in `SKILL.md` when you mention work that matches it (e.g., "retest the WAF for TC-27", "verify Coraza multipart bypasses", "produce SOC handoff for the IPS finding"). You can also invoke it explicitly with `/waf-ips-ids-retest`.

### Codex

Copy this folder into your local Codex skills directory as `waf-ips-ids-retest`, then trigger it with:

```text
$waf-ips-ids-retest
```

Codex picker UI metadata lives in [`agents/openai.yaml`](./agents/openai.yaml).

## Release Notes

- See [CHANGELOG.md](./CHANGELOG.md) for TC-24 smuggling, multi-client fan-out, hypothesis/experiment workflow updates, and Docker lab fixes.
- See [references/tc24_reference_notes.md](./references/tc24_reference_notes.md) for the external references used to shape the TC-24 runners and interpretation rules.

## Related Skills

- For the shared hypothesis / experiment workflow that sits above this skill, see [`security-hypothesis-lab`](https://github.com/windshock/security-hypothesis-lab).

## Validate

If you have Codex skill tooling available, validate the skill with the standard validator for your environment. For Claude Code, the only required surface is the YAML frontmatter at the top of `SKILL.md` (`name`, `description`); the rest is plain Markdown plus referenced files under `references/`, `assets/`, and `scripts/`.
