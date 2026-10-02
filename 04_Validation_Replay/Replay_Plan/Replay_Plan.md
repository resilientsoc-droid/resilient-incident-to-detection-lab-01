==============================================
       REPLAY PLAN — Controlled Simulation
==============================================

**Plan ID:** RP-2026-09-29-001
**Date Prepared:** 2026-09-26 (original) / Finalized 2026-09-29
**Prepared By:** Resilient Cybersecurity
**Environment:** Isolated Lab (VMware — NAT Network)
**Target Host:** DESKTOP-DI2GMCC (Win 10 VM)
**Target IP:** `192.168.x.x` (redacted, VMware NAT lab)

---

## Scenario Name
Simulated Phishing Payload → Discovery → Encoded Execution → Persistence

## Objective
Simulate a simple, realistic attack behavior to test the monitoring environment's (Sysmon + Splunk) ability to detect known MITRE ATT&CK techniques, then re-execute (replay) the same behavior after building detection rules to validate they work.

## Techniques Executed (in order)

| Order | Technique | MITRE ID | Atomic Test |
|---|---|---|---|
| 1 | System Information Discovery | T1082 | Test 1 |
| 2 | PowerShell Encoded Command Execution | T1059.001 | Test 15 |
| 3 | Scheduled Task Persistence | T1053.005 | Test 4 |

## Tool Used
Invoke-AtomicTest (Atomic Red Team, Red Canary)

## Pre-Execution State
VM Snapshot taken: `Clean_Baseline_Before_Scenario1_2026-09-26`

## Rollback Plan
In the event of any unexpected behavior, test execution is halted immediately and the VM is restored to the snapshot `Clean_Baseline_Before_Scenario1_2026-09-26`.

## Authorization
This execution takes place within a fully isolated lab environment owned entirely by the analyst, and does not target any production data or systems.

## Replay Execution (Phase 3 — Validation)

| Technique | Original Execution | Replay Execution | Alert Fired | Result |
|---|---|---|---|---|
| T1059.001-15 | 2026-09-26 19:39:30 | 2026-09-29 01:43:55 | 2026-09-29 01:45:03 | ✅ Detected |
| T1053.005-4 | 2026-09-28 01:39:49 | 2026-09-29 ~01:5x | 2026-09-29 02:05:02 | ✅ Detected |

## Post-Replay Cleanup
- `AtomicTask` scheduled task removed and confirmed deleted via `Get-ScheduledTask`.
- DET-001 and DET-002 alerts disabled after successful validation to avoid continued alerting on stale data.

## Expected Outcome
Full documentation of the resulting events (DFIR), followed by detection rule construction (Detection Engineering), then re-execution to confirm rule effectiveness (Validation) — achieved in full, as documented in the DFIR Investigation Report, Detection Package, and Validation Report.

==============================================
