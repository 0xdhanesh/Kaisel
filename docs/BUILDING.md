# Building

Kaisel builds with Xcode on macOS. The Xcode project is generated from
[`Apps/project.yml`](../Apps/project.yml) by XcodeGen, so it is not committed.

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| macOS | 14 Sonoma or later | |
| Xcode | 15.0 or later (Swift 5.9) | iOS SDK 17+; the apps deploy to iOS 15.0 |
| XcodeGen | 2.38 or later | `brew install xcodegen` |
| iPhone or iPad | iOS 15.0 to 27 | Detection only means something on a real device |
| Apple ID | free or paid | Free works for both apps; App Attest needs a paid team |
| Python | 3.10+ (optional) | Only for the reference server, the lab tools and the icon script |

## Schemes

| Scheme | App name on the phone | What it is | Apple account |
|---|---|---|---|
| `KaiselJBCheck` | Kaisel JB Check | Jailbreak-only verdict with evidence | Free or paid |
| `KaiselIntegrityCheck` | Kaisel Integrity Check | Full kit: device, runtime and app verdicts, posture, Secure Enclave seal | Free or paid |
| `KaiselIntegrityCheckAttest` | Kaisel Integrity Attest | Integrity Check plus App Attest enrolment and assertions | **Paid only** |

## Option A: Xcode (run directly on your phone)

```bash
git clone https://github.com/0xdhanesh/Kaisel.git
cd Kaisel/Apps
xcodegen generate
open Kaisel.xcodeproj
```

1. Select the `KaiselJBCheck` or `KaiselIntegrityCheck` scheme.
2. In **Signing & Capabilities**, choose your team. A free Apple ID appears as "Your Name (Personal Team)".
3. If Xcode says the bundle identifier is unavailable, change `KAISEL_BUNDLE_PREFIX` in `Apps/project.yml`
   (for example `com.yourname.kaisel`), then run `xcodegen generate` again.
4. Connect the phone, select it as the run destination and press **Run**.
5. On iOS 16 or later, enable **Settings › Privacy & Security › Developer Mode** when asked, and restart.
6. With a free Apple ID, trust the developer once: **Settings › General › VPN & Device Management**.

## Option B: Signed IPA from the command line

```bash
Scripts/build_ipa.sh --team ABCDE12345                                  # Kaisel JB Check
Scripts/build_ipa.sh --team ABCDE12345 --scheme KaiselIntegrityCheck
Scripts/build_ipa.sh --team ABCDE12345 --scheme KaiselIntegrityCheck --bundle-prefix com.yourname.kaisel
```

Your Team ID is in Xcode › Settings › Accounts, or on developer.apple.com under Membership.
The IPA is written to `build/ipa/<Scheme>.ipa`. Install it with Xcode's **Devices and Simulators**
window (drag the IPA onto the device), Apple Configurator, or `xcrun devicectl device install app`.

`--method ad-hoc` needs a paid team and the device UDIDs registered in your account.

## Option C: Unsigned IPA for sideloading tools

```bash
Scripts/build_unsigned_ipa.sh                   # both apps
Scripts/build_unsigned_ipa.sh KaiselJBCheck     # one app
```

This writes `dist/<Scheme>-<version>-unsigned.ipa` and `dist/SHA256SUMS.txt`. No developer account
is needed to build. Install with Impactor or Sideloadly, which sign the app with your Apple ID:
see [Sideloading](SIDELOADING.md). Tagged releases on GitHub publish the same files.

## Common build errors

| Error | Fix |
|---|---|
| `Personal development teams ... do not support the App Attest capability` | You built `KaiselIntegrityCheckAttest` with a free account. Build `KaiselIntegrityCheck` instead. |
| `Failed to register bundle identifier` / `is not available` | Another account already owns the ID. Set your own `KAISEL_BUNDLE_PREFIX`. |
| `The compiler is unable to type-check this expression in reasonable time` | Report it with the file and line; it is fixed by splitting the expression. |
| `No such module 'KaiselKit'` | Run `xcodegen generate` from `Apps/`, then **File › Packages › Reset Package Caches**. |
| App closes immediately after a free-account install | The 7-day profile expired or the developer is not trusted. Reinstall and trust it again. |

## Swift package only

```bash
xcodebuild -scheme KaiselKit -destination 'generic/platform=iOS' build
xcodebuild -scheme KaiselKit -destination 'platform=iOS Simulator,name=<an installed iPhone simulator>' test
```

`swift build` on macOS will not work, because the package targets iOS only.

## Regenerating generated files

| File | Command |
|---|---|
| `Sources/CIntegrityCore/rasp_strings_table.h`, `Sources/KaiselKit/ObfuscatedLists.swift` | `python3 Scripts/gen_strings.py` |
| App icons and `Branding/` | `pip install Pillow && python3 Scripts/make_kaisel_icons.py` |
| `Server/weights.json` | `python3 Server/tools/export_weights.py` |
