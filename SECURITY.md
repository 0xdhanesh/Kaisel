# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.2.x | Yes |
| < 1.2 | No |

## Reporting a vulnerability

Please **do not** open a public issue for a vulnerability.

- Preferred: [report privately through GitHub](https://github.com/0xdhanesh/Kaisel/security/advisories/new).
- Or email **dhanesh.professional@gmail.com** with the subject `Kaisel security`.

Include the affected version, the iOS version and device, steps to reproduce and the impact.
You will get an acknowledgement within 5 working days. Fixes are coordinated with the reporter, and
reporters are credited in the release notes unless they prefer otherwise.

## What counts

In scope:

- Flaws that let a forged or replayed report pass the reference server's verification.
- Signature, anti-rollback or bounds bypasses in signed remote rules.
- Memory-safety bugs in the C core.
- False positives that mark a **stock** device as jailbroken (please include the result JSON).

Generally **not** treated as vulnerabilities, but welcome as issues or pull requests:

- A new jailbreak, hiding tweak or Frida technique that is not detected. On-device detection is
  bypassable by design; see [Limitations](docs/LIMITATIONS.md). Use the *Detection gap* issue template.
- Issues in the reference server's deliberate simplifications (no TLS, no authentication, JSON storage).

## Handling sensitive data

Result JSON can contain device model, iOS version and file paths. Redact anything that identifies a
person or organisation before attaching it to an issue.
