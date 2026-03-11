#!/usr/bin/env bash
set -euo pipefail

ip route replace default via 172.30.20.254 dev eth0
exec python3 /lab/server-app.py
