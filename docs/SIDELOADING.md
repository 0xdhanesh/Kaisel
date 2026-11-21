# Sideloading with Impactor or Sideloadly

Sideloading installs an IPA onto your iPhone or iPad using your own Apple ID, without Xcode.
Both Kaisel apps work with a **free** Apple ID.

> Use an Apple ID you control. Sideloading tools send your Apple ID credentials to Apple to create a
> signing certificate; consider a secondary Apple ID rather than your main one.

## 1. Get the IPA

- **From GitHub Releases:** download `KaiselJBCheck-<version>-unsigned.ipa` and/or
  `KaiselIntegrityCheck-<version>-unsigned.ipa`, and `SHA256SUMS.txt`, from the
  [Releases page](https://github.com/0xdhanesh/Kaisel/releases). Check the hash:
  `shasum -a 256 -c SHA256SUMS.txt` (macOS) or `Get-FileHash <file> -Algorithm SHA256` (Windows).
- **Or build it yourself** on a Mac: `Scripts/build_unsigned_ipa.sh` (see [Building](BUILDING.md#option-c-unsigned-ipa-for-sideloading-tools)).

`KaiselIntegrityCheckAttest` is not distributed as an IPA: App Attest needs a paid team's provisioning
profile, which a sideloading tool cannot create.

## 2a. Install with Impactor

[Impactor](https://github.com/khcrysalis/impactor) is an open-source sideloading tool for macOS, Windows and Linux.

1. Download and install Impactor from its GitHub releases page.
2. Connect the iPhone by USB, unlock it and tap **Trust This Computer**.
3. Open Impactor and sign in with your Apple ID.
4. Select the device, choose the Kaisel IPA and start the install (button labels vary between Impactor versions; see its quick start).
5. Continue with [step 3](#3-first-launch-on-the-phone).

## 2b. Install with Sideloadly

1. Install [Sideloadly](https://sideloadly.io) (macOS or Windows; on Windows, install iTunes and iCloud from Apple's website, not the Microsoft Store).
2. Connect the iPhone by USB and trust the computer.
3. Drag the IPA into Sideloadly, enter your Apple ID and click **Start**.
4. Leave the bundle ID unchanged unless the install fails with an "already in use" error.

## 3. First launch on the phone

1. **Developer Mode (iOS 16 or later):** Settings › Privacy & Security › Developer Mode › On, then restart and confirm.
2. **Trust the developer:** Settings › General › VPN & Device Management › your Apple ID › **Trust**.
3. Open **Kaisel JB Check** or **Kaisel Integrity Check**.

## Free Apple ID limits

| Limit | Value |
|---|---|
| App lifetime | **7 days**. After that the app will not open; reinstall (re-sign) it. Paid accounts get one year. |
| Sideloaded apps per device | 3 active apps signed by the same free Apple ID |
| New App IDs | 10 per 7 days |
| Capabilities | No App Attest, push notifications or other paid-only entitlements |

Your data in the app is kept when you re-sign with the same Apple ID and bundle ID.

## How sideloading affects Kaisel's results

- **Kaisel JB Check** is not affected. It ignores how the app itself was signed.
- **Kaisel Integrity Check** shows the build as `development` (re-signed, `get-task-allow`, not FairPlay encrypted)
  and Developer Mode as on. These appear under **Informational** and do not change the **device** verdict.
  They are only scored if you set `expectedDistribution: .appStore` in your own app.
- Server verification works with a Secure Enclave seal only; start the reference server with
  `--no-require-app-attest` (see [Server](SERVER.md#reference-server)).

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Untrusted Developer" | Trust the profile in VPN & Device Management (step 3.2). |
| App opens and closes immediately | The 7-day signature expired, or Developer Mode is off. Re-sign and check both. |
| "Maximum number of apps" | Remove another sideloaded app signed by the same Apple ID. |
| Install fails with a bundle ID error | Let the tool change the bundle ID, or build with your own `--bundle-prefix`. |
| Two-factor prompt never arrives | Sign in on the tool again and accept the prompt on a trusted Apple device. |
