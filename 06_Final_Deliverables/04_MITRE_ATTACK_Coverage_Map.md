# MITRE ATT&CK Coverage Map

**Project:** Incident-to-Detection — Sample Engagement
**Prepared by:** Resilient Cybersecurity
**Date:** 2026-09-29

---

## Coverage Map

| Tactic | Technique | ID | Sub-technique Test | Observed (DFIR)? | Detection Rule Exists? | Validated? |
|---|---|---|---|---|---|---|
| Discovery | System Information Discovery | T1082 | Atomic Test 1 | ✅ | ❌ (deliberate decision — see Gap Analysis) | — |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Atomic Test 15 | ✅ | ✅ DET-001 | ✅ Detected |
| Persistence / Privilege Escalation | Scheduled Task/Job: Scheduled Task | T1053.005 | Atomic Test 4 | ✅ | ✅ DET-002 | ✅ Detected |

## Reading the Map

- **🟢 Fully covered (Observed + Detected + Validated):** T1059.001, T1053.005
- **🟡 Observed but no dedicated detection rule yet:** T1082 (recommended to address via a Baseline/UEBA strategy rather than a signature-based rule, given how common this command is in legitimate use)
- **⚪ Entirely out of scope for this cycle:** Initial Access, Lateral Movement, Defense Evasion (beyond the evasion covered under T1059.001's encoding), Credential Access, Exfiltration, Impact — these tactics were not tested in this engagement, and no coverage claim is made for them.

## Recommendation for Next Phase

Any follow-up Incident-to-Detection cycle in this same environment should expand coverage to include:
- **T1003 (Credential Access)** — via a fully controlled Mimikatz test, with explicit authorization and in an environment completely isolated from any network.
- **T1021 (Lateral Movement)** — requires adding at least a second host to the lab.
- **T1070 (Defense Evasion — Indicator Removal)** — note: a rule already exists on the server named `Archive-to-Log-Clear-Detection` that partially covers T1070.001; it is recommended to review it as part of the client's overall coverage picture.

---
*End of MITRE ATT&CK Coverage Map*
