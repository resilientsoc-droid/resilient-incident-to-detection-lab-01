# Validation Report

**Project:** Incident-to-Detection — Sample Engagement
**Prepared by:** Resilient Cybersecurity
**Date:** 2026-09-29
**Classification:** Public — Training Lab (Controlled Simulation)

> This report documents a Controlled Simulation within an isolated lab, not a test performed on a real production environment.

---

## 1. Replay Plan (Summary)

| Item | Details |
|---|---|
| Plan ID | RP-2026-09-29-001 |
| Environment | Isolated Lab (VMware, NAT network) |
| Target Host | DESKTOP-DI2GMCC (`192.168.x.x`, redacted) |
| Tool | Invoke-AtomicTest (Atomic Red Team) |
| Techniques Replayed | T1059.001-15, T1053.005-4 |
| Rollback Point | VM Snapshot: `Clean_Baseline_Before_Scenario1_2026-09-26` |
| Authorization | Analyst is the sole owner of the environment; no external authorization required in this lab context |

## 2. Replay Execution Log

| Technique | First Execution Time (Phase 1/2) | Replay Execution Time (Phase 3) |
|---|---|---|
| T1059.001-15 (Encoded Command) | 2026-09-26 19:39:30 | 2026-09-29 01:43:55 |
| T1053.005-4 (Scheduled Task) | 2026-09-28 01:39:49 | 2026-09-29 ~02:00 (based on the first matching Cron run at 02:05:02) |

Both commands executed successfully (`TestSuccess: True`, `Exit code: 0`) on both occasions, with identical underlying logic, differing naturally only in test identifiers (TestGuid) and the Base64 payload (due to a randomized GUID embedded in each run).

## 3. Alert Evidence

### DET-001 — PowerShell Encoded Command

| Item | Value |
|---|---|
| Replay Execution Time | 2026-09-29 01:43:55 |
| First Matching Alert Time | 2026-09-29 01:45:03 (Triggered Alerts) |
| Match Verification | Full CommandLine (Base64 string) matched between the `Invoke-AtomicTest` output and the rule's search result in Splunk — exact match |
| Status | ✅ **Detected** |

### DET-002 — Scheduled Task Logon Persistence

| Item | Value |
|---|---|
| Replay Execution Time | 2026-09-29 ~01:5x (after the second execution of T1053.005-4) |
| Matching Alert Time | 2026-09-29 02:05:02 (Triggered Alerts) |
| Match Verification | `Task_Name = \AtomicTask` matched between the execution result and the rule's search result |
| Status | ✅ **Detected** |

## 4. Detected / Not Detected Summary

| Rule | Technique | Status |
|---|---|---|
| DET-001 | T1059.001 | ✅ Detected |
| DET-002 | T1053.005 | ✅ Detected |

**Detection rate for this cycle: 2 of 2 (100%)** for the techniques covered by dedicated rules. (T1082 was not included in rule scope for this cycle — see Detection Gap Analysis in the Detection Package for the rationale.)

## 5. Before / After Comparison

| | Before the Project | After the Project |
|---|---|---|
| **Visibility** | Partially available (Sysmon running, but the Audit Policy for scheduled tasks was disabled) | Full visibility for both techniques |
| **Detection** | No rule or alert exists for any of the three techniques | Two active, tested rules (DET-001, DET-002) |
| **Expected Response Time** | Undefined (no alert; reliance would have been on manual log review) | Automatic alert within a maximum of 5 minutes of the event occurring (based on current test scheduling) |
| **Documentation Capability** | No pre-existing timeline or documented IOCs | Full timeline + reusable IOCs/TTPs |

## 6. Post-Validation Actions

- Both DET-001 and DET-002 were disabled after successful testing, to prevent continued alerting on stale simulation data.
- `AtomicTask` was confirmed fully removed from the host via `Get-ScheduledTask` (empty result confirms removal).
- **Before any deployment to a real production environment**, both rules must be re-enabled after completing the Tuning phase described in the Detection Package (allowlisting).

---
*End of Validation Report*
