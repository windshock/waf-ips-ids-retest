#!/usr/bin/env python3
from __future__ import annotations

import argparse

from manual_stub_common import emit_manual_stub


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a manual-only stub for TC-09 raw relay testing.")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    emit_manual_stub(
        tc="TC-09",
        title="Parser-branch or raw request gap",
        output_dir=args.output_dir,
        reason="Generic automation stops here because raw relay behavior and parser contracts are target-specific.",
        prerequisites=[
            "Working raw relay or WAFFLED-compatible sender",
            "Compatible endpoint contract",
            "Approved replay window for malformed requests",
        ],
        evidence=[
            "Raw request artifact",
            "Response or timeout artifact",
            "Parser-path note",
            "IDS or proxy correlation if available",
        ],
        next_steps=[
            "Build the target-specific raw relay path",
            "Confirm which endpoint actually accepts the intended content type",
            "Replay valid -> weak -> malformed variants against the same endpoint",
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
