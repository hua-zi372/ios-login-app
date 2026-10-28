#!/usr/bin/env python3
"""Patch ExpoModulesJSI's apple/scripts/build-xcframework.sh for Xcode 26/27.

Two independent, repeat-safe fixes:

1. (expo#50482 / PR#50587) Xcode prints a bogus line while the nested
   xcodebuild runs with `-quiet`:
     error: the following command failed with exit code 0 but produced no further output
   It is emitted for a *successful* SwiftCompile job, but the outer script phase
   parses it as a real error and fails. Dropping `-quiet` avoids the bogus line
   and makes any genuine compiler error visible.

2. (expo#46326 / PR#46377) Pin SYMROOT/OBJROOT on the nested xcodebuild so build
   products land where the script expects them (Xcode ignores
   -derivedDataPath for auto-generated SwiftPM schemes). Newer
   expo-modules-jsi already ships this, so it is a no-op there.
"""
import sys
from pathlib import Path

TARGET = Path("node_modules/expo-modules-jsi/apple/scripts/build-xcframework.sh")


def main() -> int:
    if not TARGET.exists():
        print(f"[patch] target not found: {TARGET}")
        return 1

    src = TARGET.read_text(encoding="utf-8")
    original = src

    # --- fix 1: drop -quiet so Xcode stops emitting the bogus error line ---
    quiet_line = "    -quiet \\\n"
    if quiet_line in src:
        src = src.replace(quiet_line, "", 1)
        print("[patch] removed -quiet from nested xcodebuild")
    else:
        print("[patch] -quiet not present (already removed or different layout)")

    # --- fix 2: pin SYMROOT/OBJROOT when the vendored version does not ---
    if 'SYMROOT="${BUILD_PRODUCTS_PATH}"' in src:
        print("[patch] SYMROOT/OBJROOT already pinned")
    else:
        anchor = "-parallelizeTargets \\\n"
        inject = (
            "    SYMROOT=\"${BUILD_PRODUCTS_PATH}\" \\\n"
            "    OBJROOT=\"${DERIVED_DATA_PATH}/Build/Intermediates.noindex\" \\\n"
        )
        if anchor in src:
            src = src.replace(anchor, anchor + inject, 1)
            print("[patch] pinned SYMROOT/OBJROOT")
        else:
            print("[patch] WARNING: SYMROOT anchor missing, skipped")

    if src == original:
        print("[patch] no change applied")
        return 0

    TARGET.write_text(src, encoding="utf-8")
    print("[patch] done")

    for n, line in enumerate(src.splitlines(), 1):
        if "-quiet" in line or "SYMROOT=" in line or "OBJROOT=" in line or "-parallelizeTargets" in line:
            print(f"  {n}: {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
