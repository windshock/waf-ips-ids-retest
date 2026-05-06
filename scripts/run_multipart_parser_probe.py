#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from http_probe_common import (
    curl_request,
    dump_json,
    ensure_dir,
    parse_url,
    save_raw_http_artifacts,
    send_raw_http,
    write_csv,
)


DEFAULT_ATTACK_MARKER = "__RETEST_MULTIPART_ATTACK_MARKER__"
TC_ID = "MULTIPART-PARSER"
TC_ID_H2 = "MULTIPART-H2-DOWNGRADE"


def part_headers(
    *,
    field_name: str,
    content_type_lines: list[str] | None = None,
    disposition_extra: str = "",
) -> list[bytes]:
    disposition = f'Content-Disposition: form-data; name="{field_name}"{disposition_extra}'
    lines = [disposition]
    lines.extend(content_type_lines or ["Content-Type: text/plain; charset=utf-8"])
    return [line.encode("latin-1", errors="replace") for line in lines]


def build_part(
    *,
    field_name: str,
    value: bytes,
    content_type_lines: list[str] | None = None,
    disposition_extra: str = "",
    line_sep: bytes = b"\r\n",
) -> bytes:
    headers = part_headers(
        field_name=field_name,
        content_type_lines=content_type_lines,
        disposition_extra=disposition_extra,
    )
    return line_sep.join(headers) + line_sep + line_sep + value


def build_multipart_body(
    *,
    boundary: str,
    part: bytes,
    line_sep: bytes = b"\r\n",
    preamble: bytes = b"",
    epilogue: bytes = b"",
    leading_close: bytes | None = None,
) -> bytes:
    boundary_bytes = boundary.encode("ascii")
    chunks: list[bytes] = []
    if preamble:
        chunks.append(preamble + line_sep)
    if leading_close is not None:
        chunks.append(b"--" + boundary_bytes + leading_close + line_sep)
    chunks.extend(
        [
            b"--" + boundary_bytes + line_sep,
            part + line_sep,
            b"--" + boundary_bytes + b"--" + line_sep,
        ]
    )
    if epilogue:
        chunks.append(epilogue + line_sep)
    return b"".join(chunks)


def build_h1_request(
    *,
    method: str,
    path: str,
    host: str,
    content_type: str,
    body: bytes,
    user_agent: str,
) -> bytes:
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    return "\r\n".join(headers).encode("ascii") + b"\r\n\r\n" + body


def build_cases(field_name: str, safe_value: str, attack_value: str) -> list[dict[str, object]]:
    safe_utf8 = safe_value.encode("utf-8")
    attack_utf8 = attack_value.encode("utf-8")
    attack_utf16le = attack_value.encode("utf-16le")
    safe_part = build_part(field_name=field_name, value=safe_utf8)
    attack_part = build_part(field_name=field_name, value=attack_utf8)
    attack_utf16_part = build_part(
        field_name=field_name,
        value=attack_utf16le,
        content_type_lines=["Content-Type: text/plain; charset=utf-16le"],
    )
    duplicate_part_content_type = build_part(
        field_name=field_name,
        value=attack_utf16le,
        content_type_lines=[
            "Content-Type: text/plain; charset=utf-16le",
            "Content-Type: text/plain; charset=utf-8",
        ],
    )
    charset_mismatch_part = build_part(
        field_name=field_name,
        value=attack_utf16le,
        content_type_lines=["Content-Type: text/plain; charset=utf-8"],
    )
    filename_star_part = build_part(
        field_name=field_name,
        value=attack_utf8,
        disposition_extra="; filename*=utf-8''" + quote("probe.txt", safe=""),
    )

    return [
        {
            "name": "baseline_multipart_safe",
            "boundary_header": "y",
            "body_boundary": "y",
            "body": build_multipart_body(boundary="y", part=safe_part),
            "payload_note": "valid multipart safe baseline",
        },
        {
            "name": "attack_multipart_plain",
            "boundary_header": "y",
            "body_boundary": "y",
            "body": build_multipart_body(boundary="y", part=attack_part),
            "payload_note": "valid multipart with inert attack marker",
        },
        {
            "name": "duplicate_boundary_parameter",
            "boundary_header": "y; boundary=x",
            "body_boundary": "y",
            "body": build_multipart_body(boundary="y", part=attack_part),
            "payload_note": "top-level Content-Type has duplicate boundary parameters",
        },
        {
            "name": "garbage_outside_boundary",
            "boundary_header": "y",
            "body_boundary": "y",
            "body": build_multipart_body(
                boundary="y",
                part=safe_part,
                preamble=b"garbage-before " + attack_utf8,
                epilogue=b"garbage-after " + attack_utf8,
            ),
            "payload_note": "attack marker appears outside multipart boundaries",
        },
        {
            "name": "lf_only_line_endings",
            "boundary_header": "y",
            "body_boundary": "y",
            "body": build_multipart_body(
                boundary="y",
                part=build_part(field_name=field_name, value=attack_utf8, line_sep=b"\n"),
                line_sep=b"\n",
            ),
            "payload_note": "multipart body uses LF line endings instead of CRLF",
        },
        {
            "name": "part_duplicate_content_type",
            "boundary_header": "y",
            "body_boundary": "y",
            "body": build_multipart_body(boundary="y", part=duplicate_part_content_type),
            "payload_note": "part contains duplicate Content-Type headers with different charsets",
        },
        {
            "name": "part_utf16le_charset",
            "boundary_header": "y",
            "body_boundary": "y",
            "body": build_multipart_body(boundary="y", part=attack_utf16_part),
            "payload_note": "part declares UTF-16LE and encodes marker as UTF-16LE",
        },
        {
            "name": "part_charset_mismatch",
            "boundary_header": "y",
            "body_boundary": "y",
            "body": build_multipart_body(boundary="y", part=charset_mismatch_part),
            "payload_note": "part declares UTF-8 while body bytes are UTF-16LE",
        },
        {
            "name": "boundary_end_trailing_space",
            "boundary_header": "y",
            "body_boundary": "y",
            "body": build_multipart_body(boundary="y", part=attack_part, leading_close=b"-- "),
            "payload_note": "body starts with boundary end marker containing trailing space",
        },
        {
            "name": "content_disposition_filename_star",
            "boundary_header": "y",
            "body_boundary": "y",
            "body": build_multipart_body(boundary="y", part=filename_star_part),
            "payload_note": "part Content-Disposition includes RFC5987 filename* parameter",
        },
    ]


def row_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalized_row(
    *,
    timestamp: str,
    domain: str,
    tc: str,
    protocol: str,
    case: str,
    result: dict,
    notes: str,
    payload_note: str,
    request_path: str,
    raw_response_path: str,
    payload_path: str = "",
) -> dict[str, str]:
    return {
        "timestamp": timestamp,
        "domain": domain,
        "tc": tc,
        "zone": "body",
        "payload_type": case,
        "protocol": protocol,
        "server_response_code": str(result.get("http_code", "")),
        "ids_result": "",
        "callback_state": "",
        "notes": notes,
        "case": case,
        "http_code": str(result.get("http_code", "")),
        "server_header": str(result.get("server_header", "")),
        "content_type": str(result.get("content_type", "")),
        "body_fingerprint": str(result.get("body_fingerprint", "")),
        "body_size": str(result.get("body_size", "")),
        "request_path": request_path,
        "raw_response_path": raw_response_path,
        "header_path": str(result.get("header_path", "")),
        "body_path": str(result.get("body_path", "")),
        "payload_path": payload_path,
        "payload_note": payload_note,
    }


def run_h1_cases(
    *,
    cases: list[dict[str, object]],
    url: str,
    out_dir: Path,
    method: str,
    request_host: str,
    connect_host: str,
    timeout: int,
) -> list[dict[str, str]]:
    scheme, parsed_host, port, path = parse_url(url)
    rows: list[dict[str, str]] = []
    for case in cases:
        name = str(case["name"])
        body = case["body"]
        if not isinstance(body, bytes):
            raise RuntimeError(f"{name} did not produce bytes")
        content_type = f'multipart/form-data; boundary={case["boundary_header"]}'
        request_bytes = build_h1_request(
            method=method,
            path=path,
            host=request_host,
            content_type=content_type,
            body=body,
            user_agent="RETEST-MULTIPART-H1",
        )
        out_prefix = out_dir / name
        out_prefix.with_suffix(".request.bin").write_bytes(request_bytes)
        response = send_raw_http(
            scheme=scheme,
            connect_host=connect_host or parsed_host,
            port=port,
            request_bytes=request_bytes,
            timeout=timeout,
            sni=request_host,
        )
        result = save_raw_http_artifacts(
            out_prefix,
            request_bytes.decode("latin-1", errors="replace"),
            response,
        )
        rows.append(
            normalized_row(
                timestamp=row_timestamp(),
                domain=request_host,
                tc=TC_ID,
                protocol="HTTP",
                case=name,
                result=result,
                notes=str(case["payload_note"]),
                payload_note=str(case["payload_note"]),
                request_path=str(out_prefix.with_suffix(".request.txt")),
                raw_response_path=str(result.get("raw_response_path", "")),
            )
        )
    return rows


def run_h2_curl_cases(
    *,
    cases: list[dict[str, object]],
    url: str,
    out_dir: Path,
    method: str,
    request_host: str,
    timeout: int,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for case in cases:
        name = str(case["name"])
        body = case["body"]
        if not isinstance(body, bytes):
            raise RuntimeError(f"{name} did not produce bytes")
        out_prefix = out_dir / name
        payload_path = out_prefix.with_suffix(".payload.bin")
        payload_path.write_bytes(body)
        content_type = f'multipart/form-data; boundary={case["boundary_header"]}'
        pseudo_request = {
            "transport": "HTTP/2 via curl",
            "method": method,
            "url": url,
            "headers": {
                "Host": request_host,
                "User-Agent": "RETEST-MULTIPART-H2",
                "Content-Type": content_type,
            },
            "payload_path": str(payload_path),
        }
        out_prefix.with_suffix(".request.txt").write_text(
            json.dumps(pseudo_request, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        result = curl_request(
            url=url,
            out_prefix=out_prefix,
            method=method,
            headers=[
                f"Host: {request_host}",
                "User-Agent: RETEST-MULTIPART-H2",
                f"Content-Type: {content_type}",
            ],
            body_path=payload_path,
            timeout=timeout,
            extra_args=["--http2", "-k"],
        )
        notes = str(case["payload_note"])
        if result.get("curl_rc") not in (0, "0"):
            notes = notes + f" | curl_rc={result.get('curl_rc')} stderr={result.get('stderr', '')}"
        rows.append(
            normalized_row(
                timestamp=row_timestamp(),
                domain=request_host,
                tc=TC_ID_H2,
                protocol="HTTP/2",
                case=name,
                result=result,
                notes=notes,
                payload_note=str(case["payload_note"]),
                request_path=str(out_prefix.with_suffix(".request.txt")),
                raw_response_path="",
                payload_path=str(payload_path),
            )
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run multipart/form-data parser differential probes with conservative evidence output."
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--method", default="POST")
    parser.add_argument("--field-name", default="probe")
    parser.add_argument("--safe-value", default="safe")
    parser.add_argument("--attack-value", default=DEFAULT_ATTACK_MARKER)
    parser.add_argument("--request-host")
    parser.add_argument("--connect-host")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--transport", choices=["h1", "h2", "both"], default="h1")
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    _, parsed_host, _, _ = parse_url(args.url)
    request_host = args.request_host or parsed_host
    connect_host = args.connect_host or parsed_host
    cases = build_cases(args.field_name, args.safe_value, args.attack_value)

    rows: list[dict[str, str]] = []
    if args.transport in {"h1", "both"}:
        h1_dir = out_dir if args.transport == "h1" else ensure_dir(out_dir / "h1")
        rows.extend(
            run_h1_cases(
                cases=cases,
                url=args.url,
                out_dir=h1_dir,
                method=args.method.upper(),
                request_host=request_host,
                connect_host=connect_host,
                timeout=args.timeout,
            )
        )
    if args.transport in {"h2", "both"}:
        h2_dir = out_dir if args.transport == "h2" else ensure_dir(out_dir / "h2")
        rows.extend(
            run_h2_curl_cases(
                cases=cases,
                url=args.url,
                out_dir=h2_dir,
                method=args.method.upper(),
                request_host=request_host,
                timeout=args.timeout,
            )
        )

    summary = {
        "url": args.url,
        "request_host": request_host,
        "connect_host": connect_host,
        "transport": args.transport,
        "tc_h1": TC_ID,
        "tc_h2": TC_ID_H2,
        "attack_value_default_is_inert": args.attack_value == DEFAULT_ATTACK_MARKER,
        "cases": rows,
    }
    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        [
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
            "case",
            "http_code",
            "server_header",
            "content_type",
            "body_fingerprint",
            "body_size",
            "request_path",
            "raw_response_path",
            "header_path",
            "body_path",
            "payload_path",
            "payload_note",
        ],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
