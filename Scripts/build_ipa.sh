#!/usr/bin/env bash
# Build a signed .ipa with your own Apple developer team.
#
#   Scripts/build_ipa.sh --team ABCDE12345 [--scheme KaiselJBCheck]
#                        [--method development|ad-hoc] [--bundle-prefix com.you.kaisel]
#
# Schemes: KaiselJBCheck (default), KaiselIntegrityCheck, KaiselIntegrityCheckAttest.
# A free Apple ID (Personal Team) can build KaiselJBCheck and KaiselIntegrityCheck.
# KaiselIntegrityCheckAttest needs a paid team (App Attest entitlement).
# Output: build/ipa/<Scheme>.ipa
set -euo pipefail

TEAM="" SCHEME="KaiselJBCheck" METHOD="development" PREFIX=""
usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --team) TEAM="$2"; shift 2 ;;
    --scheme) SCHEME="$2"; shift 2 ;;
    --method) METHOD="$2"; shift 2 ;;
    --bundle-prefix) PREFIX="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done
[[ -n "$TEAM" ]] || { echo "error: --team is required (Xcode > Settings > Accounts shows your Team ID)" >&2; exit 1; }
case "$SCHEME" in
  KaiselJBCheck|KaiselIntegrityCheck) ;;
  KaiselIntegrityCheckAttest) echo "note: $SCHEME needs a paid developer team; Personal Teams cannot sign App Attest." ;;
  *) echo "error: unknown scheme $SCHEME" >&2; exit 1 ;;
esac
case "$METHOD" in development|ad-hoc) ;; *) echo "error: --method must be development or ad-hoc" >&2; exit 1 ;; esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build"
mkdir -p "$OUT/ipa"
command -v xcodegen >/dev/null || { echo "error: install XcodeGen first: brew install xcodegen" >&2; exit 1; }
(cd "$ROOT/Apps" && xcodegen generate --quiet)

EXTRA=()
[[ -n "$PREFIX" ]] && EXTRA+=("KAISEL_BUNDLE_PREFIX=$PREFIX")
sed "s/YOUR_TEAM_ID/$TEAM/" "$ROOT/Apps/ExportOptions/$METHOD.plist" > "$OUT/export-$METHOD.plist"

xcodebuild -project "$ROOT/Apps/Kaisel.xcodeproj" -scheme "$SCHEME" -configuration Release \
  -destination 'generic/platform=iOS' -archivePath "$OUT/$SCHEME.xcarchive" \
  DEVELOPMENT_TEAM="$TEAM" CODE_SIGN_STYLE=Automatic ${EXTRA[@]+"${EXTRA[@]}"} \
  -allowProvisioningUpdates archive
xcodebuild -exportArchive -archivePath "$OUT/$SCHEME.xcarchive" \
  -exportOptionsPlist "$OUT/export-$METHOD.plist" -exportPath "$OUT/ipa" -allowProvisioningUpdates

echo "IPA: $OUT/ipa/$SCHEME.ipa"
