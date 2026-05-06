#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/../assets/docker-multipart-parser-lab" && pwd)"
COMPOSE="docker compose -f $LAB_DIR/docker-compose.yml"

usage() {
  cat <<'EOF'
Usage:
  docker_multipart_parser_lab.sh up
  docker_multipart_parser_lab.sh down
  docker_multipart_parser_lab.sh probe <output_dir>
  docker_multipart_parser_lab.sh logs <output_dir>
EOF
}

detect_connect_host() {
  if [[ -n "${LAB_CONNECT_HOST:-}" ]]; then
    printf '%s\n' "$LAB_CONNECT_HOST"
    return
  fi
  if getent hosts host.docker.internal >/dev/null 2>&1; then
    printf '%s\n' "host.docker.internal"
    return
  fi
  printf '%s\n' "127.0.0.1"
}

wait_ready() {
  local tries=0
  local connect_host
  connect_host="$(detect_connect_host)"
  while [[ $tries -lt 20 ]]; do
    if curl -ksS --connect-timeout 1 --max-time 2 "http://$connect_host:19380/health" >/dev/null 2>&1 \
      && curl -ksS --connect-timeout 1 --max-time 2 "http://$connect_host:19381/health" >/dev/null 2>&1; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 1
  done
  return 1
}

run_probe() {
  local out_dir="$1"
  local connect_host
  connect_host="$(detect_connect_host)"
  mkdir -p "$out_dir/waf" "$out_dir/backend" "$out_dir/h2-edge"

  python3 "$SCRIPT_DIR/run_multipart_parser_probe.py" \
    --url http://127.0.0.1:19380/parse \
    --connect-host "$connect_host" \
    --request-host multipart.example.local \
    --output-dir "$out_dir/waf"

  python3 "$SCRIPT_DIR/run_multipart_parser_probe.py" \
    --url http://127.0.0.1:19381/parse \
    --connect-host "$connect_host" \
    --request-host multipart.example.local \
    --output-dir "$out_dir/backend"

  python3 "$SCRIPT_DIR/run_multipart_parser_probe.py" \
    --url https://localhost:19443/parse \
    --request-host localhost \
    --transport h2 \
    --output-dir "$out_dir/h2-edge"
}

cmd="${1:-}"
case "$cmd" in
  up)
    $COMPOSE up -d --remove-orphans
    ;;
  down)
    $COMPOSE down -v
    ;;
  probe)
    out_dir="${2:-}"
    if [[ -z "$out_dir" ]]; then
      usage
      exit 1
    fi
    wait_ready
    run_probe "$out_dir"
    ;;
  logs)
    out_dir="${2:-}"
    if [[ -z "$out_dir" ]]; then
      usage
      exit 1
    fi
    mkdir -p "$out_dir"
    $COMPOSE logs --no-color >"$out_dir/compose.log"
    ;;
  *)
    usage
    exit 1
    ;;
esac
