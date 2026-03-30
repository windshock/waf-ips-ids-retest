#!/bin/sh
set -eu

usage() {
  cat >&2 <<'EOF'
usage: run_tc24_multiip_probe.sh --clients N --hidden-count N --output-dir DIR --docker-network NAME --target-url URL [options]

required:
  --clients N
  --hidden-count N
  --output-dir DIR
  --docker-network NAME
  --target-url URL

optional:
  --connect-host NAME   TCP connect host override inside the Docker network
  --request-host NAME   Host/SNI override
  --trigger-path PATH   Override trigger path from target URL
  --hidden-path PATH    Path used for hidden smuggled GETs (default: /)
  --timeout SECONDS     Per-client read timeout (default: 120)
  --client-image IMAGE  Docker image used for probe clients (default: python:3.12-alpine)
EOF
  exit 2
}

CLIENTS=""
HIDDEN_COUNT=""
OUTPUT_DIR=""
DOCKER_NETWORK=""
TARGET_URL=""
CONNECT_HOST=""
REQUEST_HOST=""
TRIGGER_PATH=""
HIDDEN_PATH="/"
TIMEOUT="120"
CLIENT_IMAGE="python:3.12-alpine"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --clients) CLIENTS="$2"; shift 2 ;;
    --hidden-count) HIDDEN_COUNT="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --docker-network) DOCKER_NETWORK="$2"; shift 2 ;;
    --target-url) TARGET_URL="$2"; shift 2 ;;
    --connect-host) CONNECT_HOST="$2"; shift 2 ;;
    --request-host) REQUEST_HOST="$2"; shift 2 ;;
    --trigger-path) TRIGGER_PATH="$2"; shift 2 ;;
    --hidden-path) HIDDEN_PATH="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --client-image) CLIENT_IMAGE="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[ -n "$CLIENTS" ] || usage
[ -n "$HIDDEN_COUNT" ] || usage
[ -n "$OUTPUT_DIR" ] || usage
[ -n "$DOCKER_NETWORK" ] || usage
[ -n "$TARGET_URL" ] || usage

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

mkdir -p "$OUTPUT_DIR"

i=1
while [ "$i" -le "$CLIENTS" ]; do
  cid=$(printf "c%03d" "$i")
  set -- \
    python /work/tc24_multiip_client.py \
    --target-url "$TARGET_URL" \
    --hidden-path "$HIDDEN_PATH" \
    --hidden-count "$HIDDEN_COUNT" \
    --client-id "$cid" \
    --timeout "$TIMEOUT"
  if [ -n "$CONNECT_HOST" ]; then
    set -- "$@" --connect-host "$CONNECT_HOST"
  fi
  if [ -n "$REQUEST_HOST" ]; then
    set -- "$@" --request-host "$REQUEST_HOST"
  fi
  if [ -n "$TRIGGER_PATH" ]; then
    set -- "$@" --trigger-path "$TRIGGER_PATH"
  fi
  docker run --rm \
    -u "${HOST_UID}:${HOST_GID}" \
    --network "$DOCKER_NETWORK" \
    -v "$SCRIPT_DIR:/work:ro" \
    "$CLIENT_IMAGE" \
    "$@" \
      >"$OUTPUT_DIR/$cid.stdout.txt" 2>"$OUTPUT_DIR/$cid.stderr.txt" &
  i=$((i + 1))
done

wait

python3 - <<'PY' "$OUTPUT_DIR" "$HIDDEN_COUNT"
import csv
import json
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
hidden_count = int(sys.argv[2])
rows = []
for path in sorted(out_dir.glob("c*.stdout.txt")):
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        continue
    rows.append(json.loads(text))

if not rows:
    raise SystemExit("no client summaries found")

summary_path = out_dir / "summary.csv"
with summary_path.open("w", encoding="utf-8", newline="") as handle:
    fieldnames = list(rows[0].keys())
    writer = csv.DictWriter(handle, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

expected_200 = hidden_count + 1
full = sum(
    1
    for row in rows
    if int(row["count_200"]) == expected_200
    and int(row["count_400"]) == 0
    and int(row["count_502"]) == 0
    and int(row["markers_seen"]) == hidden_count
    and row["error"] == ""
)
partial = sum(
    1
    for row in rows
    if int(row["count_200"]) > 0
    or int(row["count_400"]) > 0
    or int(row["count_403"]) > 0
    or int(row["count_405"]) > 0
    or int(row["count_502"]) > 0
)
degraded = sum(1 for row in rows if not (
    int(row["count_200"]) == expected_200
    and int(row["count_400"]) == 0
    and int(row["count_502"]) == 0
    and int(row["markers_seen"]) == hidden_count
    and row["error"] == ""
))
meta = {
    "clients": len(rows),
    "hidden_count": hidden_count,
    "expected_200_per_client": expected_200,
    "full_success_clients": full,
    "clients_with_any_response": partial,
    "degraded_clients": degraded,
    "summary_csv": str(summary_path),
}
(out_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
print(json.dumps(meta, separators=(",", ":")))
PY
