#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/../assets/docker-response-origin-lab" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  docker_response_origin_lab.sh up
  docker_response_origin_lab.sh down
  docker_response_origin_lab.sh probe <output_dir>
EOF
}

cmd="${1:-}"
case "$cmd" in
  up)
    docker compose -f "$LAB_DIR/docker-compose.yml" up -d --remove-orphans
    ;;
  down)
    docker compose -f "$LAB_DIR/docker-compose.yml" down -v
    ;;
  probe)
    out_dir="${2:-}"
    if [[ -z "$out_dir" ]]; then
      usage
      exit 1
    fi
    mkdir -p "$out_dir"
    declare -a cases=(
      "edge403|http://127.0.0.1:18080/edge403"
      "spring_pass|http://127.0.0.1:18080/proxy/spring-pass"
      "spring_intercept|http://127.0.0.1:18080/proxy/spring-intercept"
      "tomcat_pass|http://127.0.0.1:18080/proxy/tomcat-pass"
      "tomcat_intercept|http://127.0.0.1:18080/proxy/tomcat-intercept"
      "appjson_pass|http://127.0.0.1:18080/proxy/appjson-pass"
      "spring_direct|http://127.0.0.1:18081/"
      "tomcat_direct|http://127.0.0.1:18082/"
      "appjson_direct|http://127.0.0.1:18083/"
      "hold_direct|http://127.0.0.1:18084/"
    )
    for entry in "${cases[@]}"; do
      name="${entry%%|*}"
      url="${entry#*|}"
      hdr="$out_dir/$name.hdr"
      body="$out_dir/$name.body"
      err="$out_dir/$name.err"
      : > "$hdr"
      : > "$body"
      code="$(curl -sS --connect-timeout 2 --max-time 5 -o "$body" -D "$hdr" -w '%{http_code}' "$url" 2>"$err" || echo ERR)"
      printf '%s %s\n' "$name" "$code"
    done
    python3 "$SCRIPT_DIR/classify_response_origin.py" --directory "$out_dir" --output "$out_dir/classification.json"
    ;;
  *)
    usage
    exit 1
    ;;
esac
