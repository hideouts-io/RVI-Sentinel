#!/bin/zsh

set -euo pipefail

readonly PROJECT_DIR="${0:A:h:h}"
readonly BUNDLE_DIR="$PROJECT_DIR/dist/RVI-Sentinel.app"
readonly CONTENTS_DIR="$BUNDLE_DIR/Contents"
readonly MACOS_DIR="$CONTENTS_DIR/MacOS"
readonly RESOURCES_DIR="$CONTENTS_DIR/Resources"
readonly CLANG_EXECUTABLE="$(/usr/bin/xcrun --find clang)"
readonly MACOS_SDK="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"

mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
/usr/bin/ditto "$PROJECT_DIR/packaging/macos/Info.plist" "$CONTENTS_DIR/Info.plist"
"$CLANG_EXECUTABLE" -std=c17 -Wall -Wextra -Werror \
  -isysroot "$MACOS_SDK" -mmacosx-version-min=13.0 \
  "$PROJECT_DIR/packaging/macos/launcher.c" \
  -o "$MACOS_DIR/RVI-Sentinel"
/usr/bin/ditto "$PROJECT_DIR/assets/RVI-Sentinel.icns" "$RESOURCES_DIR/RVI-Sentinel.icns"
/usr/bin/touch "$BUNDLE_DIR"

print "$BUNDLE_DIR"
