#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from http_probe_common import dump_json, ensure_dir, extract_header, write_csv


def rewrite_scheme(url: str, scheme: str, port_override: int | None = None) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = port_override if port_override is not None else parsed.port
    default_port = 443 if scheme == "https" else 80
    if port in {None, default_port}:
        netloc = host
    else:
        netloc = f"{host}:{port}"
    return urlunparse(parsed._replace(scheme=scheme, netloc=netloc))


def file_hash(path: Path) -> str:
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def classify_transport(curl_rc: int, stderr: str, http_code: str) -> str:
    if curl_rc == 0 and http_code and http_code != "000":
        return f"http-response:{http_code}"
    lower = stderr.lower()
    if "timed out" in lower or "timeout" in lower:
        return "timeout"
    if "failed to connect" in lower or "could not connect" in lower:
        return "connect-failed"
    if "connection reset" in lower:
        return "connection-reset"
    if "empty reply from server" in lower:
        return "empty-reply"
    if "refused" in lower:
        return "connection-refused"
    if curl_rc != 0:
        return "curl-error"
    return "unknown"


def run_case(
    *,
    url: str,
    out_prefix: Path,
    method: str,
    headers: list[str],
    body_file: str | None,
    timeout: int,
    insecure: bool,
) -> dict[str, str]:
    hdr_path = out_prefix.with_suffix(".hdr")
    body_path = out_prefix.with_suffix(".body")
    metrics_format = json.dumps(
        {
            "http_code": "%{http_code}",
            "time_total": "%{time_total}",
            "remote_ip": "%{remote_ip}",
            "scheme": "%{scheme}",
            "num_connects": "%{num_connects}",
        }
    )
    cmd = [
        "curl",
        "--connect-timeout",
        str(min(timeout, 5)),
        "-m",
        str(timeout),
        "-sS",
        "-o",
        str(body_path),
        "-D",
        str(hdr_path),
        "-w",
        metrics_format,
        "-X",
        method,
        url,
    ]
    if insecure:
        cmd.append("-k")
    for header in headers:
        cmd.extend(["-H", header])
    if body_file:
        cmd.extend(["--data-binary", f"@{body_file}"])
    proc = subprocess.run(cmd, text=True, capture_output=True)
    metrics = {}
    if proc.stdout.strip():
        try:
            metrics = json.loads(proc.stdout.strip())
        except json.JSONDecodeError:
            metrics = {"http_code": "000", "time_total": "", "remote_ip": "", "scheme": "", "num_connects": ""}
    http_code = str(metrics.get("http_code", "000") or "000")
    header_text = hdr_path.read_text(encoding="utf-8", errors="replace") if hdr_path.exists() else ""
    result = {
        "url": url,
        "http_code": http_code,
        "curl_rc": str(proc.returncode),
        "stderr": proc.stderr.strip(),
        "time_total": str(metrics.get("time_total", "")),
        "remote_ip": str(metrics.get("remote_ip", "")),
        "scheme": str(metrics.get("scheme", "")),
        "num_connects": str(metrics.get("num_connects", "")),
        "server_header": extract_header(header_text, "Server"),
        "content_type": extract_header(header_text, "Content-Type"),
        "body_fingerprint": file_hash(body_path),
        "header_path": str(hdr_path),
        "body_path": str(body_path),
    }
    result["transport_outcome"] = classify_transport(proc.returncode, result["stderr"], http_code)
    dump_json(out_prefix.with_suffix(".json"), result)
    return result


def compare_results(http_result: dict[str, str], https_result: dict[str, str]) -> dict[str, str]:
    same_body = http_result.get("body_fingerprint") == https_result.get("body_fingerprint")
    same_code = http_result.get("http_code") == https_result.get("http_code")
    return {
        "http_transport_outcome": http_result.get("transport_outcome", ""),
        "https_transport_outcome": https_result.get("transport_outcome", ""),
        "http_http_code": http_result.get("http_code", ""),
        "https_http_code": https_result.get("http_code", ""),
        "same_http_code": "true" if same_code else "false",
        "same_body_fingerprint": "true" if same_body else "false",
        "interpretation": build_interpretation(http_result, https_result, same_code, same_body),
    }


def build_interpretation(
    http_result: dict[str, str], https_result: dict[str, str], same_code: bool, same_body: bool
) -> str:
    http_outcome = http_result.get("transport_outcome", "")
    https_outcome = https_result.get("transport_outcome", "")
    if http_outcome == "timeout" and https_outcome.startswith("http-response:"):
        return "plaintext-http timed out while https returned an HTTP response"
    if https_outcome == "timeout" and http_outcome.startswith("http-response:"):
        return "https timed out while plaintext-http returned an HTTP response"
    if same_code and same_body and http_outcome.startswith("http-response:") and https_outcome.startswith("http-response:"):
        return "http and https behaved the same for this path"
    if http_outcome.startswith("http-response:") and https_outcome.startswith("http-response:"):
        return "both schemes returned HTTP responses, but response family differed"
    return "scheme behavior differed; inspect curl_rc, stderr, and headers before attributing to IPS"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare plaintext HTTP and HTTPS behavior for the same path and, when provided, the same payload before attributing timeouts to IPS."
    )
    parser.add_argument("--https-url", required=True)
    parser.add_argument("--http-url", help="Optional explicit plaintext URL. Defaults to the https URL rewritten to http://")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--method", default="GET", help="HTTP method to send on both schemes")
    parser.add_argument("--header", action="append", default=[], help="Repeatable header applied to both schemes")
    parser.add_argument("--body-file", help="Optional request body file applied to both schemes")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--insecure", action="store_true", help="Allow invalid TLS certs for the HTTPS side")
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    https_url = args.https_url
    http_url = args.http_url or rewrite_scheme(args.https_url, "http")

    https_result = run_case(
        url=https_url,
        out_prefix=out_dir / "https",
        method=args.method.upper(),
        headers=args.header,
        body_file=args.body_file,
        timeout=args.timeout,
        insecure=args.insecure,
    )
    http_result = run_case(
        url=http_url,
        out_prefix=out_dir / "http",
        method=args.method.upper(),
        headers=args.header,
        body_file=args.body_file,
        timeout=args.timeout,
        insecure=False,
    )

    comparison = compare_results(http_result, https_result)
    dump_json(out_dir / "comparison.json", comparison)
    write_csv(
        out_dir / "summary.csv",
        [
            "scheme_case",
            "url",
            "scheme",
            "transport_outcome",
            "http_code",
            "curl_rc",
            "time_total",
            "remote_ip",
            "num_connects",
            "server_header",
            "content_type",
            "body_fingerprint",
            "header_path",
            "body_path",
            "stderr",
        ],
        [
            {
                "scheme_case": "http",
                **http_result,
            },
            {
                "scheme_case": "https",
                **https_result,
            },
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
