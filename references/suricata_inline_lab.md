# Suricata Inline Lab

Use this reference when you need to decide whether an observed `403`, timeout, or reset is compatible with an IPS-style inline block, and you want a deterministic local comparison.

## Goal

Build a small Docker lab where Suricata sits inline between a client and a server, enforces `drop` rules, and produces `eve.json` evidence.

This lab is for:

- proving what an inline block looks like from the client side
- comparing `drop` behavior against front-proxy `403` behavior
- testing candidate rules before applying the logic to a real retest

## Topology

- `client` on `172.30.10.10`
- `sensor` on `172.30.10.254` and `172.30.20.254`
- `server` on `172.30.20.10`

The sensor acts as the gateway and queues forwarded packets to Suricata using `NFQUEUE`.

## Why NFQUEUE here

On macOS with Docker Desktop, a host-inline IPS is not the right target. Use a container-internal routed lab instead:

- routed traffic is easy to force through the sensor container
- `NFQUEUE` gives real `accept/drop` verdicts
- the lab stays deterministic and self-contained

## Default rules

The lab starts with four `drop` rules in `assets/docker-suricata-inline-lab/local.rules`:

- URI `/blocked`
- header `${jndi:`
- body `${jndi:`
- Unicode body `\\u0024\\u007bjndi:`

These are not meant to be production rules. They are deterministic controls for verifying:

- normal pass path
- IPS-like block path
- body and header matching
- simple segmentation/encoding follow-up experiments

## Run

Use:

- `scripts/docker_suricata_inline_lab.sh up`
- `scripts/docker_suricata_inline_lab.sh probe <output_dir>`
- `scripts/docker_suricata_inline_lab.sh logs <output_dir>`
- `scripts/docker_suricata_inline_lab.sh down`

## Interpret

- `get_ok` or `post_benign` should pass
- `get_blocked`, `header_jndi`, `post_jndi_body`, `post_unicode_body` should time out or fail from the client perspective
- `eve.json` should show `drop` alerts with the matching SID

If the client sees a clean `403`, that usually means the packet was not silently dropped inline; compare it with the response-origin lab before calling it IPS behavior.
