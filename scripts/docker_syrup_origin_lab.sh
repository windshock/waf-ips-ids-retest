#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/../assets/docker-syrup-origin-lab" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  docker_syrup_origin_lab.sh up
  docker_syrup_origin_lab.sh down
  docker_syrup_origin_lab.sh probe <output_dir>
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
      "web_redirect|http://127.0.0.1:19090/notice.do|Host: www.syrup.co.kr"
      "web_attack_hold|http://127.0.0.1:19090/notice.do|Host: www.syrup.co.kr|X-Test: \${jndi:ldap://lab/a}"
      "front400|http://127.0.0.1:19090/__lab/front400|Host: lab-front.invalid"
      "front403|http://127.0.0.1:19090/__lab/front403|Host: lab-front.invalid"
      "next_auth|http://127.0.0.1:19090/auth/|Host: nxt.syrup.co.kr"
      "next_fallback|http://127.0.0.1:19090/auth/|Host: wrong-nxt.syrup.co.kr"
      "next_register|http://127.0.0.1:19090/gold-platform/register-password/|Host: nxt.syrup.co.kr"
      "appjson_ok|http://127.0.0.1:19270/swapp/sw5/5667|Host: syrup-appif.smartwallet.co.kr"
      "appjson_fail|http://127.0.0.1:19270/swapp/sw5/5667|Host: syrup-appif.smartwallet.co.kr|Content-Type: text/plain"
      "static_css|http://127.0.0.1:19090/static/v2/publishing/syrup_intro_2025/css/style_pc.css|Host: static.syrup.co.kr"
    )
    for entry in "${cases[@]}"; do
      IFS='|' read -r name url header_a header_b <<<"$entry"
      hdr="$out_dir/$name.hdr"
      body="$out_dir/$name.body"
      err="$out_dir/$name.err"
      : > "$hdr"
      : > "$body"
      args=(curl -sS --connect-timeout 2 --max-time 5 -o "$body" -D "$hdr" -w '%{http_code}' "$url")
      if [[ -n "${header_a:-}" ]]; then
        args+=(-H "$header_a")
      fi
      if [[ -n "${header_b:-}" ]]; then
        args+=(-H "$header_b")
      fi
      code="$("${args[@]}" 2>"$err" || echo ERR)"
      printf '%s %s\n' "$name" "$code"
    done
    python3 "$SCRIPT_DIR/classify_response_origin.py" --directory "$out_dir" --output "$out_dir/classification.json"
    ;;
  *)
    usage
    exit 1
    ;;
esac
