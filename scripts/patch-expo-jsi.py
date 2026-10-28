#!/usr/bin/env python3
"""Fix ExpoModulesJSI nested xcodebuild on Xcode 26.

Refs:
  - expo/expo issue #46326  (nested xcodebuild -> "Supported platforms ... empty")
  - expo/expo PR    #46377  (official fix: pin SYMROOT/OBJROOT)

Xcode 26 ignores -derivedDataPath for the auto-generated SwiftPM scheme used by
ExpoModulesJSI and writes build products outside DERIVED_DATA_PATH, so the
"did not produce framework" check in build-xcframework.sh fails (exit 65).
Pinning SYMROOT/OBJROOT on the nested xcodebuild invocation forces the products
back into the expected location. On Xcode versions that honor -derivedDataPath
this is a no-op.
"""
import sys
from pathlib import Path

TARGET = Path("node_modules/expo-modules-jsi/apple/scripts/build-xcframework.sh")


def main() -> int:
    if not TARGET.exists():
        print(f"[patch] target not found: {TARGET}")
        return 1

    src = TARGET.read_text(encoding="utf-8")

    marker = 'SYMROOT="${BUILD_PRODUCTS_PATH}"'
    if marker in src:
        print("[patch] already patched, nothing to do")
        return 0

    anchor = "-parallelizeTargets \\\n"
    inject = (
        "    SYMROOT=\"${BUILD_PRODUCTS_PATH}\" \\\n"
        "    OBJROOT=\"${DERIVED_DATA_PATH}/Build/Intermediates.noindex\" \\\n"
    )

    if anchor not in src:
        idx = src.find("-parallelizeTargets")
        print("[patch] ANCHOR NOT FOUND, dumping context for inspection")
        if idx >= 0:
            print(src[max(0, idx - 120): idx + 320])
        return 1

    src = src.replace(anchor, anchor + inject, 1)
    TARGET.write_text(src, encoding="utf-8")
    print("[patch] patched OK")

    for n, line in enumerate(src.splitlines(), 1):
        if "SYMROOT=" in line or "OBJROOT=" in line or "-parallelizeTargets" in line:
            print(f"  {n}: {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
