#!/usr/bin/env bash
# Build unsigned .ipa files for sideloading tools (Impactor, Sideloadly, AltStore),
# which re-sign the app with your Apple ID on install. No developer account needed
# to build; Xcode and XcodeGen are required.
#
#   Scripts/build_unsigned_ipa.sh                 # both free-account apps
#   Scripts/build_unsigned_ipa.sh KaiselJBCheck   # one app
#
# Output: dist/<Scheme>-<version>-unsigned.ipa
# KaiselIntegrityCheckAttest is not offered: App Attest needs a paid team's
# provisioning profile, which a sideloading tool cannot add.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCHEMES=("$@")
[[ ${#SCHEMES[@]} -gt 0 ]] || SCHEMES=(KaiselJBCheck KaiselIntegrityCheck)
VERSION="$(sed -n 's/^ *MARKETING_VERSION: *"\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$ROOT/Apps/project.yml" | head -1)"
BUILD="$ROOT/build/unsigned"
DIST="$ROOT/dist"
mkdir -p "$BUILD" "$DIST"

command -v xcodegen >/dev/null || { echo "error: install XcodeGen first: brew install xcodegen" >&2; exit 1; }
(cd "$ROOT/Apps" && xcodegen generate --quiet)

for SCHEME in "${SCHEMES[@]}"; do
  case "$SCHEME" in
    KaiselJBCheck|KaiselIntegrityCheck) ;;
    *) echo "error: $SCHEME cannot be built unsigned (use KaiselJBCheck or KaiselIntegrityCheck)" >&2; exit 1 ;;
  esac
  ARCHIVE="$BUILD/$SCHEME.xcarchive"
  rm -rf "$ARCHIVE" "$BUILD/Payload"
  xcodebuild -project "$ROOT/Apps/Kaisel.xcodeproj" -scheme "$SCHEME" -configuration Release \
    -destination 'generic/platform=iOS' -archivePath "$ARCHIVE" \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" VALIDATE_PRODUCT=NO \
    archive | if command -v xcpretty >/dev/null; then xcpretty; else cat; fi
  APP="$(find "$ARCHIVE/Products/Applications" -maxdepth 1 -name '*.app' | head -1)"
  [[ -d "$APP" ]] || { echo "error: no .app in $ARCHIVE" >&2; exit 1; }
  mkdir -p "$BUILD/Payload"
  cp -R "$APP" "$BUILD/Payload/"
  IPA="$DIST/$SCHEME-$VERSION-unsigned.ipa"
  rm -f "$IPA"
  (cd "$BUILD" && zip -qry "$IPA" Payload)
  rm -rf "$BUILD/Payload"
  echo "IPA: $IPA"
done
(cd "$DIST" && shasum -a 256 ./*-unsigned.ipa > SHA256SUMS.txt)
echo "Checksums: $DIST/SHA256SUMS.txt"
