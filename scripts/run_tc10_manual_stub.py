#!/usr/bin/env python3
from __future__ import annotations

import argparse

from manual_stub_common import emit_manual_stub


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a manual-only stub for TC-10 encrypted visibility testing.")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    emit_manual_stub(
        tc="TC-10",
        title="Encrypted visibility gap",
        output_dir=args.output_dir,
        reason="Generic automation stops here because TC-10 needs a real app encryptor, live key material, and an accepted endpoint contract.",
        prerequisites=[
            "Real app-side encryptor or equivalent code path",
            "Key material for the active crypt level",
            "Accepted plaintext and encrypted control requests for the same endpoint",
        ],
        evidence=[
            "Encryptor metadata",
            "Plaintext request and response",
            "Encrypted request and response",
            "IDS visibility note",
        ],
        next_steps=[
            "Capture a valid control request first",
            "Derive or obtain the correct key flow for the target crypt level",
            "Compare plaintext and encrypted variants against the same endpoint contract",
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
