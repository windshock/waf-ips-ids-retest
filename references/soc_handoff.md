# SOC Handoff Guidance

Deliver evidence in a way the SOC can correlate without reinterpreting the test.

## Always include

- run id
- source IP
- timezone
- callback domain and callback health state
- environment mode
- SSL visibility statement
- CSV path and row count
- exact query windows

## Explain constraints explicitly

Record these separately from test outcomes:

- HTTPS visibility unavailable
- callback infrastructure unstable
- blocked TCs
- not-run TCs
- unknown blocking owner

## Do not say

- "No callback means no execution"
- "HTTPS 200 means IDS missed it"
- "No alert means vulnerability confirmed"

## Preferred summary structure

1. environment and visibility
2. reproduced key findings
3. blocked or inconclusive areas
4. exact query windows for correlation
