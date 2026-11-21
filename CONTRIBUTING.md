# Contributing to Kaisel

Thank you for helping. The most valuable contributions are:

1. **Lab results** from real jailbroken or instrumented devices (see [docs/LAB.md](docs/LAB.md)).
2. **False-positive reports** from stock devices, with the result JSON.
3. **New indicators** for current jailbreaks, hiding tweaks and instrumentation tools.
4. Documentation fixes.

All contributions must come from authorised testing on devices you own or are permitted to test.

## Development setup

```bash
brew install xcodegen
git clone https://github.com/0xdhanesh/Kaisel.git && cd Kaisel
cd Apps && xcodegen generate && open Kaisel.xcodeproj
```

Reference server and tools:

```bash
cd Server && python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python3 -m unittest discover -s tests
```

## Ground rules for detection changes

- **No false positives on stock devices.** A signal that a stock, sealed iOS can produce must not be
  `conclusive` and must not be a hard indicator. Explain in the pull request why the new evidence is
  impossible on a stock device, or mark it as an indicator.
- **No plaintext indicators.** Add paths, library markers and URL schemes to `Scripts/gen_strings.py`
  and regenerate with `python3 Scripts/gen_strings.py`. Commit the generated files.
- **URL schemes** must be audited against every stock Apple app on iOS 15 to 27 before being added.
- **Weights** live in `Sources/KaiselKit/Finding.swift`. After changing them, run
  `python3 Server/tools/export_weights.py` so the server stays in sync.
- Add or update the expectation in `Lab/expected.json` for any new finding code.

## Pull requests

1. Fork, then branch from `main` (`feature/…`, `fix/…`, `detect/…`).
2. Keep pull requests focused; one detection technique per pull request is ideal.
3. Make sure CI passes: the package and both apps build, and the server tests pass.
4. Update `CHANGELOG.md` under **Unreleased**.
5. Fill in the pull request template, including how you tested and on which iOS versions.

## Style

- Swift: follow the existing style; avoid long chained expressions that slow the type checker.
- C: C11, `-Wall -Wextra` clean, no heap allocation in the hot path, raw syscalls through `rasp_internal.h`.
- Python: standard library first, PEP 8.
- Docs: British English, concise and technical.

## Commit messages

Use the imperative mood, for example `Detect ElleKit loader on iOS 17`. Reference issues with `Fixes #123`.

## Licence

By contributing you agree that your contributions are licensed under the [MIT licence](LICENSE).
