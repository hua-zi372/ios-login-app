#!/usr/bin/env python3
"""Patch ExpoModulesJSI for Xcode 26.3 / Swift 6.2 compatibility.

Run this BEFORE `pod install` (the podspec change must be picked up when
CocoaPods writes the pods xcconfig) and before the Xcode build (the script
change is used by the [CP-User] Build ExpoModulesJSI xcframework phase).

1. podspec: lower SWIFT_VERSION 6.0 -> 5.0 for this pod only.
   Xcode 26.3 ships Swift 6.2 which fails ExpoModulesJSI with
     JavaScriptObject.swift:946: error: sending 'slot' risks causing data races
   Swift 5 language mode disables that check for this pod only.

2. build-xcframework.sh: drop `-quiet` from the nested xcodebuild.
   (expo#50482: Xcode prints a bogus "exit code 0 but produced no further
   output" error line under -quiet and the outer phase treats it as fatal.)

3. build-xcframework.sh: pin SYMROOT/OBJROOT when not already present.
   (expo#46326 / PR#46377; newer expo-modules-jsi already ships this.)
"""
import re
import sys
from pathlib import Path

PODSPEC = Path("node_modules/expo-modules-jsi/apple/ExpoModulesJSI.podspec")
BUILD_SCRIPT = Path("node_modules/expo-modules-jsi/apple/scripts/build-xcframework.sh")


def patch_podspec() -> None:
    if not PODSPEC.exists():
        print(f"[patch] podspec not found: {PODSPEC}")
        return
    src = PODSPEC.read_text(encoding="utf-8")
    if re.search(r"s\.swift_version\s*=\s*'5\.0'", src):
        print("[patch] podspec already Swift 5.0")
        return
    new, n = re.subn(r"s\.swift_version\s*=\s*'6\.0'", "s.swift_version  = '5.0'", src, count=1)
    if n == 0:
        print("[patch] WARNING: podspec swift_version pattern not found")
        return
    PODSPEC.write_text(new, encoding="utf-8")
    print("[patch] podspec: SWIFT_VERSION 6.0 -> 5.0")


def patch_build_script() -> None:
    if not BUILD_SCRIPT.exists():
        print(f"[patch] build script not found: {BUILD_SCRIPT}")
        return
    src = BUILD_SCRIPT.read_text(encoding="utf-8")
    original = src

    quiet_line = "    -quiet \\\n"
    if quiet_line in src:
        src = src.replace(quiet_line, "", 1)
        print("[patch] removed -quiet from nested xcodebuild")
    else:
        print("[patch] -quiet not present")

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
            print("[patch] WARNING: SYMROOT anchor missing")

    if src == original:
        print("[patch] build script unchanged")
        return
    BUILD_SCRIPT.write_text(src, encoding="utf-8")
    print("[patch] build script updated")


def main() -> int:
    patch_podspec()
    patch_build_script()
    return 0


if __name__ == "__main__":
    sys.exit(main())
