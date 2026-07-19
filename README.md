# kql-library

A growing library of **KQL hunting and detection queries** for Microsoft Defender XDR and Microsoft Sentinel, run from the unified SecOps portal ([security.microsoft.com](https://security.microsoft.com)).

Every query is standalone, documented in a header block, and organised so you can find it by what the attacker is *doing*.

## Naming convention

**Folder = MITRE ATT&CK tactic. File = technique + short description.**

```
<tactic>/T<technique>-<kebab-description>.kql
```

Examples:

| File | Reads as |
|------|----------|
| `credential-access/T1003.001-lsass-comsvcs-minidump.kql` | Credential Access → LSASS dump via comsvcs |
| `impact/T1490-backup-db-service-termination.kql` | Impact → inhibit recovery by killing backups |
| `command-and-control/T1572-tunnelling-revsocks-chisel-cloudflared.kql` | C2 → protocol tunnelling |

Rules:

- **Tactic folder** uses the ATT&CK tactic in kebab-case (`credential-access`, `defense-evasion`, `command-and-control`, `lateral-movement`, `impact`, …).
- **File name** starts with the primary technique ID (`T1003.001`), then a short kebab description. Pick the primary technique where a query spans several.
- Indicator-match queries that map to no single technique live in `ioc-matching/` and are named by what they match.

## Query header

Every `.kql` file opens with a standard comment block:

```
// Name        : <human-readable name>
// Technique   : <TID - ATT&CK name>
// Tactic      : <ATT&CK tactic>
// Platform    : <Defender XDR / Sentinel - Advanced Hunting>
// Data source : <primary table(s)>
// Description : <what it finds>
// Tuning      : <false-positive guidance before alerting>
// References  : <source>
```

## Current contents

| Tactic | Query |
|--------|-------|
| Credential Access | `T1003.001-lsass-comsvcs-minidump` |
| Defense Evasion | `T1562.001-defender-tamper-disable` |
| Command and Control | `T1572-tunnelling-revsocks-chisel-cloudflared` |
| Lateral Movement | `T1021.001-rdp-enable-and-local-admin-add` |
| Impact | `T1490-backup-db-service-termination`, `T1486-ransom-note-artifact` |
| Indicator matching | `known-hashes-filenames-sweep`, `watchlist-driven-ioc-match` |

## How to use

1. In [security.microsoft.com](https://security.microsoft.com), open **Hunting → Advanced hunting**.
2. Paste a query, adjust the `ago(30d)` window, and **Run query**.
3. Once tuned against your estate, promote high-value queries to a **Defender custom detection** or a **Sentinel scheduled analytics rule** — both from the unified portal.

The `watchlist-driven-ioc-match` query expects a Sentinel watchlist from the companion [`threat-intel`](https://github.com/azurebeard/threat-intel) repo.

## Caveats

- **Tune before you alert.** Queries use a broad window and generic living-off-the-land filters. Hunt first, learn what's normal, then alert.
- Behavioural queries survive an attacker rotating their infrastructure; static IOC matches do not. Use both.

## License

[MIT](LICENSE).
