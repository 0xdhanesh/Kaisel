# Assessment scenarios (P2)

Repeatable scenarios for measuring which existing Kaisel detectors respond to instrumentation, jailbreaks
and hiding. They are measurement plans, not new detection: a heuristic is added only after it has been
shown not to fire on stock devices (see [COVERAGE.md](COVERAGE.md)).

Run them only on devices you own or are authorised to test, with tools obtained from their official
sources. This document says what to set up and what to record. It does not describe how to build, modify
or conceal instrumentation or jailbreak tooling.

Each scenario key matches [`expected.json`](expected.json). Record every run with
[`templates/RESULT_RECORD.md`](templates/RESULT_RECORD.md) and
[`templates/run.meta.json`](templates/run.meta.json), and export JSON from both apps.

Keep the two questions apart throughout: **is the device jailbroken?** (Kaisel JB Check, device domain)
and **is this process instrumented?** (runtime domain). Frida on its own never makes a device "Jailbroken".

## Runtime instrumentation (Frida)

| Key | Set-up | Record | Expected (hypothesis) |
|---|---|---|---|
| `frida_server` | Jailbroken lab device, frida-server running, Frida attached to the already running Kaisel Integrity Check with a simple hook | Codes 500, 501, 502, 503, 504, 205, 300, 301, 306, 610, 1000 | Runtime high or compromised. Device verdict comes from the jailbreak, not from Frida |
| `frida_spawn` | Same device, the app spawned under Frida | As above | Runtime high or compromised, detected at first evaluation |
| `frida_gadget` | Stock device, an authorised lab build of Kaisel Integrity Check repackaged with FridaGadget and re-signed | 205, 500, 503, 504, 603, 900, 901, 601, server App Attest result | Runtime high or compromised; JB Check *Not jailbroken* or *Suspicious*, never *Jailbroken* |
| `frida_renamed` | Authorised test environment where instrumentation file and thread names are not Frida's defaults | 201, 206, 503, 504, 300, 301, 306, 610, 901, 1000 | Name-based detectors (205, 500) miss. Record which behaviour-based detectors still respond |
| `frida_late_attach` | Evaluate once with nothing attached, then attach, then **Evaluate now** again with IntegrityMonitor running | 203, 205, 206, 500, 504, 306, 610, 1003 | The second evaluation reports the late image (203 plus its class) or runtime hooks |

## Jailbreaks and hiding

| Key | Set-up | Record | Expected (hypothesis) |
|---|---|---|---|
| `palera1n_rootless` | palera1n rootless on a checkm8 device | 105, 100, 200, 905, 202 | Jailbroken |
| `palera1n_rootful` | palera1n rootful (fakefs), where the device supports it | 104, 103, 102, 100 | Jailbroken |
| `dopamine` | Dopamine, no hiding | 105, 100, 200, 701, 905 | Jailbroken |
| `dopamine_hidden` | Dopamine with a hiding tweak enabled for the app | 108, 202, 300, 301, 304, 305 | Suspicious or Jailbroken |
| `dopamine_roothide` | Dopamine + RootHide, app **not** on the Blacklist | 200 (`roothideinit.dylib`), 905 | Jailbroken. **Measured: PASS** (see COVERAGE.md) |
| `dopamine_roothide_hidden` | Dopamine + RootHide, app on the Blacklist | 110, 111, 908, every code that survives | Target Suspicious. **Measured: missed** (known gap) |
| `dopamine_roothide_hidden_fresh` | Blacklist on a fresh install that never ran unhidden | 110, 111 | Expected miss today; measures what survives with no memory |
| `dopamine_roothide_hidden_seen` | Blacklist after a verified unhidden run of the same install; reference server in strict mode | 908 on the device; server decision and reason | Device Suspicious (908); server `deny` with "previously seen" |
| `shadow_class_hiding` | Jailbroken device with a Shadow-class hiding tweak enabled for the app | 108, 202, 300, 301, 303, 304, 305, 201, 206 | Suspicious or Jailbroken (hooks on file and dyld APIs are visible) |

For every hiding scenario, write down which checks still produced evidence and which stopped. Those that
survive hiding are the strongest signals; those that stop are documented as limitations.

## False-positive guard

Before any detection change is scored, run the `stock` scenario on every stock device available
(currently iPhone18,1 on iOS 27.2.1 and an iOS 26 device) and confirm no conclusive finding and no scored
signal. A new heuristic that fires on a stock device is not shipped.
