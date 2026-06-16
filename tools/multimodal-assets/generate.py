#!/usr/bin/env python3
"""Regenerate the multimodal probe assets from their canary payloads.

Non-destructive by default: writes regenerated images to an output directory
(``./regen`` by default) and never touches the committed assets. Pass
``--in-place`` to overwrite the committed files under the repo's data root
(use deliberately, e.g. when rotating a canary alongside the Go probe).

Usage:
    python3 generate.py                 # write all reproducible assets to ./regen
    python3 generate.py --out /tmp/x    # custom output dir
    python3 generate.py --probe multimodal.SteganographicLSB
    python3 generate.py --in-place      # overwrite committed assets (careful)
"""

from __future__ import annotations

import argparse
import os
import sys

from manifest import ASSET_ROOT, ASSETS
from techniques import ENCODERS, _CANVAS  # noqa: F401  (_CANVAS kept for parity)
from manifest import payload


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="regen", help="output directory (default: ./regen)")
    ap.add_argument("--in-place", action="store_true",
                    help="overwrite committed assets under the repo data root")
    ap.add_argument("--probe", help="only regenerate this probe's asset(s)")
    ap.add_argument("--repo-root", default=os.getcwd(),
                    help="repo root for --in-place (default: cwd)")
    args = ap.parse_args()

    written, skipped = 0, 0
    for spec in ASSETS:
        if args.probe and spec.probe != args.probe:
            continue
        if not spec.reproducible:
            print(f"SKIP  {spec.probe:38s} {spec.technique} (not reproducible in-repo)")
            skipped += 1
            continue
        encode = ENCODERS[spec.technique][0]
        data = encode(payload(spec.canary))

        if args.in_place:
            dest = os.path.join(args.repo_root, ASSET_ROOT, spec.path)
        else:
            dest = os.path.join(args.out, spec.path)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(data)
        print(f"WROTE {spec.probe:38s} -> {dest} ({len(data)} bytes)")
        written += 1

    print(f"\n{written} written, {skipped} skipped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
