#!/usr/bin/env bash
set -euo pipefail

mkdir -p /var/log/suricata
: > /var/log/suricata/eve.json

sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -F
iptables -P FORWARD ACCEPT
iptables -I FORWARD -j NFQUEUE --queue-num 0

for iface in eth0 eth1; do
  ip link set "$iface" up
  ethtool -K "$iface" gro off gso off tso off lro off rx off tx off >/dev/null 2>&1 || true
done

suricata --build-info | grep -i NFQ || true

exec suricata -c /lab/suricata.yaml -q 0 -vv
