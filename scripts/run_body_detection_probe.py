#!/usr/bin/env python3
"""Body-native attack payload detection probe.

Generate inert attack payloads inside a captured JSON request contract,
send each over HTTPS and optionally HTTP, and record transport outcomes.

Usage:
    python3 run_body_detection_probe.py \
        --contract-file ./request_contract.json \
        --target-path ReqData.ReqBody.probe \
        --output-dir ./body_detection \
        [--http-url http://host:port/path] \
        [--cooldown 3] \
        [--baseline-interval 5]
"""

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import time
import copy


PAYLOAD_CATEGORIES = {
    "sqli_union": "' UNION SELECT 1,2,3--",
    "sqli_or": "' OR '1'='1",
    "ssrf_internal": "http://169.254.169.254/latest/meta-data/",
    "ssrf_file": "file:///etc/passwd",
    "ssti_jinja": "{{7*7}}",
    "ssti_freemarker": "${7*7}",
    "nosqli_ne": '{"$ne": null}',
    "nosqli_gt": '{"$gt": ""}',
    "ldap_wildcard": "*)(&",
    "ldap_injection": "*(|(objectClass=*))",
    "rce_pipe": "; cat /etc/passwd",
    "rce_backtick": "`id`",
    "xss_script": "<script>alert(1)</script>",
    "xss_img": "<img src=x onerror=alert(1)>",
    "log4shell_jndi": "${jndi:ldap://probe.invalid/detect}",
    "path_traversal": "../../../../../../etc/passwd",
}


def set_nested(obj, path, value):
    keys = path.split(".")
    for k in keys[:-1]:
        obj = obj.setdefault(k, {})
    obj[keys[-1]] = value


def run_curl(url, body_json, headers, output_prefix, timeout=15):
    hdr_file = output_prefix + ".hdr"
    body_file = output_prefix + ".body"
    req_file = output_prefix + ".request.json"

    with open(req_file, "w") as f:
        json.dump(body_json, f, ensure_ascii=False)

    cmd = [
        "curl", "-s", "-S",
        "--max-time", str(timeout),
        "--connect-timeout", "10",
        "-X", "POST",
        "-D", hdr_file,
        "-o", body_file,
        "-w", '{"http_code":"%{http_code}","time_total":"%{time_total}","exitcode":"%{exitcode}"}',
    ]
    for k, v in headers.items():
        cmd.extend(["-H", f"{k}: {v}"])
    cmd.extend(["--data-binary", f"@{req_file}", url])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        curl_rc = result.returncode
        try:
            stats = json.loads(result.stdout)
        except Exception:
            stats = {"http_code": "000", "time_total": "0", "exitcode": str(curl_rc)}

        body_fp = ""
        if os.path.isfile(body_file):
            with open(body_file, "rb") as f:
                body_fp = hashlib.sha256(f.read()).hexdigest()[:16]

        return {
            "http_code": int(stats.get("http_code", "0")),
            "curl_rc": curl_rc,
            "time_total": float(stats.get("time_total", "0")),
            "body_fingerprint": body_fp,
        }
    except subprocess.TimeoutExpired:
        return {
            "http_code": 0,
            "curl_rc": 28,
            "time_total": timeout,
            "body_fingerprint": "",
        }


def transport_outcome(r):
    if r["curl_rc"] == 28:
        return "timeout"
    elif r["curl_rc"] == 35:
        return "reset"
    elif r["curl_rc"] != 0:
        return f"curl-error-{r['curl_rc']}"
    elif r["http_code"] == 0:
        return "no-response"
    else:
        return f"http-response:{r['http_code']}"


def main():
    parser = argparse.ArgumentParser(description="Body-native attack detection probe")
    parser.add_argument("--contract-file", required=True)
    parser.add_argument("--target-path", required=True, help="Dot-separated path for probe value")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--http-url", default=None, help="Plaintext HTTP URL for parity")
    parser.add_argument("--cooldown", type=int, default=3, help="Seconds between probes")
    parser.add_argument("--baseline-interval", type=int, default=5, help="Re-check baseline every N payloads")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    with open(args.contract_file) as f:
        contract = json.load(f)

    https_url = contract["url"]
    http_url = args.http_url or https_url.replace("https://", "http://")
    headers = contract["headers"]
    base_body = contract["body"]

    os.makedirs(args.output_dir, exist_ok=True)

    results = []
    baseline_ok = True
    probe_count = 0

    print(f"{'Payload':<25} {'HTTPS':>10} {'HTTP':>10}  Interpretation")
    print("-" * 70)

    for name, probe_val in PAYLOAD_CATEGORIES.items():
        # Periodic baseline check
        if probe_count > 0 and probe_count % args.baseline_interval == 0:
            prefix = os.path.join(args.output_dir, f"baseline_check_{probe_count}")
            bl = run_curl(https_url, base_body, headers, prefix, args.timeout)
            bl_to = transport_outcome(bl)
            if "timeout" in bl_to:
                print(f"  *** baseline check at probe #{probe_count}: TIMEOUT — IP may be blocked ***")
                baseline_ok = False
            else:
                print(f"  *** baseline check at probe #{probe_count}: {bl_to} — OK ***")
                baseline_ok = True
            time.sleep(args.cooldown)

        body = copy.deepcopy(base_body)
        set_nested(body, args.target_path, probe_val)

        prefix_https = os.path.join(args.output_dir, f"https_{name}")
        https_r = run_curl(https_url, body, headers, prefix_https, args.timeout)
        time.sleep(1)

        prefix_http = os.path.join(args.output_dir, f"http_{name}")
        http_r = run_curl(http_url, body, headers, prefix_http, args.timeout)

        https_to = transport_outcome(https_r)
        http_to = transport_outcome(http_r)

        if "timeout" in https_to or "timeout" in http_to:
            interp = "blocking-owner-unknown" if not baseline_ok else "detected"
        elif https_r["http_code"] == 403 or http_r["http_code"] == 403:
            interp = "detected"
        else:
            interp = "not-blocked"

        print(f"{name:<25} {https_to:>10} {http_to:>10}  {interp}")

        results.append({
            "payload_name": name,
            "probe_value": probe_val,
            "https_code": https_r["http_code"],
            "https_transport": https_to,
            "https_time": https_r["time_total"],
            "http_code": http_r["http_code"],
            "http_transport": http_to,
            "http_time": http_r["time_total"],
            "baseline_ok_at_time": baseline_ok,
            "interpretation": interp,
        })

        probe_count += 1
        time.sleep(args.cooldown)

    # Final baseline check
    prefix = os.path.join(args.output_dir, "baseline_final")
    bl = run_curl(https_url, base_body, headers, prefix, args.timeout)
    bl_to = transport_outcome(bl)
    print(f"\n  *** final baseline check: {bl_to} ***")

    with open(os.path.join(args.output_dir, "summary.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    csv_path = os.path.join(args.output_dir, "summary.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    detected = [r for r in results if r["interpretation"] == "detected"]
    unknown = [r for r in results if r["interpretation"] == "blocking-owner-unknown"]
    clean = [r for r in results if r["interpretation"] == "not-blocked"]

    print(f"\nTotal: {len(results)} payloads")
    print(f"  detected: {len(detected)}")
    print(f"  blocking-owner-unknown: {len(unknown)}")
    print(f"  not-blocked: {len(clean)}")
    print(f"  final baseline: {bl_to}")


if __name__ == "__main__":
    main()
