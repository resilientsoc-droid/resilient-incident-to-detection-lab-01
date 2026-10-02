# Chain of Custody Log

**Project:** Incident-to-Detection — Sample Engagement
**Prepared by:** Resilient Cybersecurity
**Date:** 2026-09-29

---

## Evidence Custody Log

| # | Evidence | Source | Date/Time | Collection Method | Responsible | Integrity Notes |
|---|---|---|---|---|---|---|
| 1 | Sysmon Event Log (Operational) | DESKTOP-DI2GMCC | 2026-09-26 to 2026-09-29 | Direct export via Splunk Universal Forwarder (automatic push) | Analyst (environment owner) | Data stored within the Splunk index (`index=sysmon`); original source logs were not modified |
| 2 | Windows Security Event Log | DESKTOP-DI2GMCC | 2026-09-28 to 2026-09-29 | Direct export via Splunk Universal Forwarder | Analyst | Same condition as above (`index=wineventlog`) |
| 3 | Execution and result screenshots (32 captures) | Splunk screen / PowerShell on Win 10 and analyst's machine | 2026-09-26 to 2026-09-29 | Direct screen capture at the time of each event | Analyst | Stored with numbered, dated filenames within the project folder structure |
| 4 | Sigma Rule files (.yml) | Manually authored based on investigation findings | 2026-09-28 | Direct authoring + saved in UTF-8 encoding | Analyst | Contains no sensitive data; fully shareable with the client |

## Copy Handling Policy

All analysis was performed directly on Splunk data (a collected copy of original logs via Forwarder); the original `.evtx` Event Log files on the source Windows machine were never modified at any point.

## Storage

Data is stored within:
1. The analyst's local Splunk index (encrypted per Splunk's default storage settings).
2. The project folder structure on the analyst's local disk (`Incident-to-Detection-Lab-01\`), with access restricted to the machine owner only.

## Destruction

**Open item:** A final destruction date has not yet been defined, as this is a training/sample engagement rather than an actual third-party contract. In any real engagement, this item must be explicitly defined in the scoping document (e.g., destruction within 30 days of final delivery, with written notice).

## Confidentiality

This is a training/sample document. In the context of a real client engagement, a Non-Disclosure Agreement (NDA) must be signed before any work begins, and the client's name or any of their specific details may not be used in any marketing material without explicit written consent.

---
*End of Chain of Custody Log*
