# Lab run: <scenario> on <device> (iOS <version>)

Copy this file to `Lab/results/<date>_<device>_<ios>_<scenario>.md`. Keep the exported JSON and its
`.meta.json` beside it (see [compare_results.py](../compare_results.py)). Redact personal identifiers,
internal app names and local paths before publishing.

| Field | Value |
|---|---|
| Kaisel version and commit | |
| Device / iOS (exact) | |
| Jailbreak or instrumentation tool and version | |
| Install method | |
| Scenario key (`Lab/expected.json`) | |
| App hidden from injection? | yes / no (which hiding list) |
| Prior jailbreak history on this install? | none / Keychain marker / server history |
| Evidence | exported JSON / screenshots only |

## Expected versus observed

| App | Expected (from `expected.json`) | Observed verdict | Findings (code, confidence) | Checks complete? | Outcome |
|---|---|---|---|---|---|
| Kaisel JB Check | | | | | PASS / PARTIAL / FAIL / NOT TESTED |
| Kaisel Integrity Check | | | | | PASS / PARTIAL / FAIL / NOT TESTED |
| Reference server (if used, mode) | | | | | |

`python3 Lab/compare_results.py --require-metadata Lab/results/<files>.json` output:

```
<paste>
```

## Detector response (P2 scenarios)

Mark each detector that responded (code and confidence) or did not respond.

| Detector | Codes | Responded? |
|---|---|---|
| Frida threads | 500 | |
| Frida D-Bus / port | 502, 501 | |
| Memory markers / anonymous executable memory | 504, 503 | |
| Loaded-image classification | 200, 205, 206, 201, 203 | |
| Inline hooks / prologue change | 300, 306 | |
| Symbol rebinding / foreign symbol | 301, 305 | |
| Code signing and app integrity | 600-610, 900-907 | |
| Check completion | 1000 | |

## Reproduction steps

1.

## Limitations of this run

-
