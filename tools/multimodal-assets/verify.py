#!/usr/bin/env python3
"""Verify that the multimodal probe assets carry their expected canaries.

Two independent checks:

  round-trip   For every technique with a decoder, encode the canary, decode it
               back, and assert the canary survives. Proves the in-repo
               generator/decoder pair is correct.

  committed    For techniques whose committed-file format is known, decode the
               ACTUAL committed asset under the repo and assert its canary is
               present. Proves the shipped bytes match the declared canary (the
               drift guard finding #3 is about, but enforced at the asset level).

Typography techniques are render-only: the verifier confirms a non-empty image
is produced but cannot read the text back (OCR is out of scope — see the
follow-up note below). Techniques marked not-reproducible in the manifest
(neural stego, scaling, scene composites) are reported as KNOWN GAPS rather than
failures; closing them is tracked as follow-up work.

Exit code is non-zero if any round-trip or committed check fails.

Usage:
    python3 verify.py                 # round-trip checks
    python3 verify.py --check-committed --repo-root /path/to/augustus
"""

from __future__ import annotations

import argparse
import os
import sys

from manifest import ASSET_ROOT, ASSETS, payload
from techniques import COMMITTED_DECODERS, ENCODERS


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check-committed", action="store_true",
                    help="also decode the committed assets and check their canaries")
    ap.add_argument("--repo-root", default=os.getcwd(),
                    help="repo root for --check-committed (default: cwd)")
    args = ap.parse_args()

    failures: list[str] = []
    gaps: list[str] = []

    print("== round-trip ==")
    for spec in ASSETS:
        if not spec.reproducible:
            gaps.append(f"{spec.probe} [{spec.technique}]")
            continue
        encode, decode = ENCODERS[spec.technique]
        data = encode(payload(spec.canary))
        if not data:
            failures.append(f"{spec.probe}: encoder produced no bytes")
            continue
        if decode is None:
            print(f"  RENDER  {spec.probe:40s} {len(data):>7d}B (no decoder; OCR out of scope)")
            continue
        recovered = decode(data)
        ok = spec.canary in recovered
        print(f"  {'OK ' if ok else 'FAIL':6s} {spec.probe:40s} canary={'found' if ok else 'MISSING'}")
        if not ok:
            failures.append(f"{spec.probe}: round-trip lost canary (got {recovered!r:.80})")

    if args.check_committed:
        print("\n== committed assets ==")
        for spec in ASSETS:
            dec = COMMITTED_DECODERS.get(spec.technique)
            if dec is None:
                continue
            path = os.path.join(args.repo_root, ASSET_ROOT, spec.path)
            if not os.path.exists(path):
                failures.append(f"{spec.probe}: committed asset missing at {path}")
                print(f"  FAIL  {spec.probe:40s} missing {path}")
                continue
            with open(path, "rb") as fh:
                recovered = dec(fh.read())
            ok = spec.canary in recovered
            print(f"  {'OK ' if ok else 'FAIL':6s} {spec.probe:40s} canary={'found' if ok else 'MISSING'}")
            if not ok:
                failures.append(f"{spec.probe}: committed asset missing canary {spec.canary!r}")

    if gaps:
        print("\n== known gaps (not reproducible in-repo, tracked as follow-up) ==")
        for g in gaps:
            print(f"  GAP  {g}")

    print()
    if failures:
        print(f"FAILED ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"OK: all reproducible assets verified; {len(gaps)} known gaps tracked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
