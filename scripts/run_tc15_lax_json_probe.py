#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from http_probe_common import curl_request, dump_json, ensure_dir, write_csv


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-15 lax JSON and partial-parse probes.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--method", default="POST")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    cases = [
        ("valid_json", '{"q":"safe"}'),
        ("single_quote_json", "{'q':'safe'}"),
        ("unquoted_key_json", '{q:"safe"}'),
        ("trailing_comma_json", '{"q":"safe",}'),
        ("comment_json", '{"q":"safe"/*comment*/}'),
        ("nan_json", '{"q":NaN}'),
    ]

    rows: list[dict[str, str]] = []
    summary = {"url": args.url, "cases": []}
    for name, body_text in cases:
        body_path = out_dir / f"{name}.payload.json"
        write_text(body_path, body_text)
        result = curl_request(
            url=args.url,
            out_prefix=out_dir / name,
            method=args.method,
            headers=["Content-Type: application/json"],
            body_path=body_path,
            timeout=args.timeout,
        )
        metadata = {"case": name, "payload": body_text, "result": result}
        dump_json(out_dir / f"{name}.meta.json", metadata)
        summary["cases"].append(metadata)
        rows.append(
            {
                "case": name,
                "http_code": result["http_code"],
                "server_header": result["server_header"],
                "content_type": result["content_type"],
                "body_fingerprint": result["body_fingerprint"],
                "header_path": result["header_path"],
                "body_path": result["body_path"],
                "payload_path": str(body_path),
            }
        )

    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        ["case", "http_code", "server_header", "content_type", "body_fingerprint", "header_path", "body_path", "payload_path"],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
