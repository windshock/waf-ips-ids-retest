#!/usr/bin/env bash
set -euo pipefail

ip route replace default via 172.30.10.254 dev eth0
sleep infinity
