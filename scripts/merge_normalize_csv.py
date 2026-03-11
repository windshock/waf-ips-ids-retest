#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path

from common import normalize_key


OUTPUT_HEADER = [
    "timestamp",
    "domain",
    "tc",
    "zone",
    "payload_type",
    "protocol",
    "server_response_code",
    "ids_result",
    "callback_state",
    "notes",
]

FIELD_ALIASES = {
    "timestamp": {"timestamp", "time", "datetime", "시각"},
    "domain": {"domain", "host", "target", "도메인"},
    "tc": {"tc", "testcase"},
    "zone": {"zone", "위치"},
    "payload_type": {"payloadtype", "payload", "description", "설명", "페이로드유형"},
    "protocol": {"protocol", "프로토콜"},
    "server_response_code": {"serverresponsecode", "response", "responsecode", "httpcode", "서버응답코드"},
    "ids_result": {"idsresult", "alert", "event", "탐지결과", "ids이벤트"},
    "callback_state": {"callback", "callbackstate", "interactsh", "콜백", "interactsh콜백여부"},
    "notes": {"note", "notes", "비고", "tool", "도구", "serverresponsesummary", "서버응답요약"},
}


def parse_input_spec(spec: str) -> tuple[Path, str]:
    if "::" in spec:
        path_str, proto = spec.rsplit("::", 1)
        return Path(path_str), proto
    return Path(spec), ""


def detect_field_map(headers: list[str]) -> dict[str, str]:
    normalized = {normalize_key(header): header for header in headers}
    field_map: dict[str, str] = {}
    for canonical, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            key = normalize_key(alias)
            if key in normalized:
                field_map[canonical] = normalized[key]
                break
    return field_map


def get_value(row: dict[str, str], field_map: dict[str, str], canonical: str, default: str = "") -> str:
    header = field_map.get(canonical)
    if not header:
        return default
    return (row.get(header) or "").strip()


def normalize_row(row: dict[str, str], field_map: dict[str, str], default_protocol: str) -> dict[str, str]:
    payload = get_value(row, field_map, "payload_type")
    notes_bits = []

    tool = get_value(row, field_map, "notes")
    if tool:
        notes_bits.append(tool)

    normalized = {
        "timestamp": get_value(row, field_map, "timestamp"),
        "domain": get_value(row, field_map, "domain"),
        "tc": get_value(row, field_map, "tc"),
        "zone": get_value(row, field_map, "zone"),
        "payload_type": payload,
        "protocol": get_value(row, field_map, "protocol", default_protocol),
        "server_response_code": get_value(row, field_map, "server_response_code"),
        "ids_result": get_value(row, field_map, "ids_result"),
        "callback_state": get_value(row, field_map, "callback_state"),
        "notes": " | ".join(bit for bit in notes_bits if bit),
    }

    if not normalized["payload_type"] and normalized["notes"]:
        normalized["payload_type"] = normalized["notes"]
        normalized["notes"] = ""
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Merge heterogeneous retest CSV files into a normalized schema."
    )
    parser.add_argument(
        "--input-spec",
        action="append",
        required=True,
        help="Input CSV path, optionally with default protocol as path::PROTO",
    )
    parser.add_argument("--output", required=True, help="Output CSV path")
    args = parser.parse_args()

    rows: list[dict[str, str]] = []
    seen = set()

    for spec in args.input_spec:
        path, default_protocol = parse_input_spec(spec)
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                continue
            field_map = detect_field_map(reader.fieldnames)
            for row in reader:
                normalized = normalize_row(row, field_map, default_protocol)
                key = tuple(normalized[column] for column in OUTPUT_HEADER)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(normalized)

    rows.sort(key=lambda item: item["timestamp"])
    output = Path(args.output)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_HEADER)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Merged {len(rows)} rows into {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
