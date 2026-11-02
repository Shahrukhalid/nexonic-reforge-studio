#!/usr/bin/env bash
# Usage: make_dmg.sh <arch-label>   (AppleSilicon | Intel). Unsigned unless signing secrets are configured.
set -euo pipefail
LABEL="${1:?arch label}"
APP="dist/Nexonic ReForge Studio.app"
OUT="dist/Nexonic_ReForge_Studio_macOS_${LABEL}.dmg"
if [[ -n "${MACOS_SIGN_IDENTITY:-}" ]]; then
  codesign --deep --force --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" "$APP"
fi
STAGE=$(mktemp -d); cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "Nexonic ReForge Studio" -srcfolder "$STAGE" -ov -format UDZO "$OUT"
if [[ -n "${APPLE_NOTARY_PROFILE:-}" ]]; then
  xcrun notarytool submit "$OUT" --keychain-profile "$APPLE_NOTARY_PROFILE" --wait && xcrun stapler staple "$OUT"
fi
echo "built $OUT"
