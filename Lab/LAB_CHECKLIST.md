# Lab validation checklist

Run only on test devices you own or are authorised to test. The goal is to
measure, on real jailbroken and instrumented devices, which signals fire, and
to catch false positives on stock devices. Nothing in this kit has yet been
validated on many jailbroken devices yet: the first record is
[Dopamine + RootHide on iOS 15.8.2](results/2026-11-21_iphone9-3_ios15.8.2_dopamine-roothide.md).
Until this checklist is completed, treat the expectations in `expected.json` as hypotheses.

## Devices to cover

| Device | iOS | Purpose |
|---|---|---|
| Any stock iPhone, latest iOS (e.g. iPhone18,1 / iOS 27) | 27.x | False-positive baseline. Already run once with v1.0. |
| A12+ device on iOS 15.0-16.6.1 | 15/16 | Dopamine (rootless), with and without a hiding tweak |
| A8-A11 device (iPhone 8/X) | 15/16 | palera1n rootless and rootful |
| Any device on 15.0-16.6.1 or 17.0 | | TrollStore install |
| Jailbroken device + frida-server | any | Frida attach and spawn |
| Stock device | any | FridaGadget-repackaged IPA |

## Per scenario

1. Install **Kaisel JB Check** and **Kaisel Integrity Check** (see [docs/BUILDING.md](../docs/BUILDING.md)).
2. Set up the scenario exactly as described in `expected.json`.
3. Open each app, wait for the result, tap **Copy result JSON**, and paste it into
   `Lab/results/<scenario>__<app>__<device-ios>.json`, for example
   `dopamine__jbcheck__iphonexs-16.5.json`.
4. Record the jailbreak/tool versions and any tweaks enabled in `Lab/results/NOTES.md`.
5. Optional, but valuable: repeat with the app opened a second time, after
   attaching Frida, and after enabling or disabling the hiding tweak.

Scenario keys: `stock`, `xcode_debugger`, `dopamine`, `dopamine_hidden`,
`dopamine_roothide`, `dopamine_roothide_hidden`,
`palera1n_rootless`, `palera1n_rootful`, `trollstore`, `frida_server`, `frida_gadget`.

## RootHide (Dopamine) scenarios

1. **`dopamine_roothide`**: install both apps, make sure neither is in RootHide's **Blacklist**, run, export.
2. **`dopamine_roothide_hidden`**: in the RootHide app, enable both Kaisel apps in **Blacklist**, force-quit
   them, open again, run, export.
3. Run the hidden case twice: once on a fresh install (no history), and once after an unhidden run
   (tests `previouslyJailbroken` and the server history).
4. Note whether `kern.userspacereboottime` fired (111) and whether `dyldModified` (110) fired.
   If 110 fires on any **stock** device, report it immediately as a false positive.

## Check the results

```bash
python3 Lab/compare_results.py Lab/results/*.json
```

Each row prints PASS, FAIL or SKIP and the codes that fired. Send back the table,
`NOTES.md` and the JSON files. The results contain no personal data: they hold
device model, iOS version, finding codes and file paths of jailbreak artefacts.

## Frida scenario commands (jailbroken device)

```bash
frida-ps -U | grep -i integrity
frida -U -n KaiselIntegrityCheck -e 'Interceptor.attach(Module.getExportByName(null, "stat"), {onEnter(){}})'
# then tap "Evaluate now" in Kaisel Integrity Check and copy the result
```

## What to look for

- **Stock devices**: any `scored` signal is a false positive. Report it with the
  `detail` text. This matters most.
- **Jailbroken devices**: which codes fire, and whether the hiding tweak
  removes them. The codes that survive hiding are your strongest signals.
- `checkSuppressed`, `prologueChanged` or `textModified` appearing means a
  bypass tool is actively patching the kit. Note which tool.
