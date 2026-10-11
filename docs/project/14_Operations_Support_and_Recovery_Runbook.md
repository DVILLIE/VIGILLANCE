# D'Vielle — Operations, Support and Recovery Runbook

Version 1.0 • 10 October 2026 • Proposed operational procedure

## Operating states

Healthy means declared sensors are current and required action/verification components work. Degraded means a capability is unavailable or stale. OutcomeUnknown means an operation's effect is not established. RecoveryRequired means unresolved owned changes need reconciliation. A responsive GUI alone does not establish protection health.

Monitor collector freshness, dropped events, store availability, unresolved intent, helper authentication/health, verification age, update freshness and total resource use. Keep local status usable offline.

## Startup

Read unresolved journals before new mutations. Validate schema/version compatibility and protected policy. Identify supported platform capabilities. Start bounded collectors, then analysis/UI. If recovery records are corrupt, preserve them, disable conflicting actions and present a diagnostic route. Do not erase them to restore a green status.

## Containment incident

1. Identify operation, target and authorization.
2. Read executor/journal state and current policy.
3. Observe actual connection behavior within approved scope.
4. Mark verified, failed or unknown accordingly.
5. Preserve supporting evidence and expected user disruption.
6. If restoration is requested, compare ownership/current state before writing.
7. Verify restored behavior and retain the final outcome.

Do not advise disabling the entire firewall or antivirus to fix application compatibility.

## Failure procedures

**Storage full/unavailable:** stop new mutations, retain essential recovery capacity, pause optional collection and explain data loss. Delete only approved expendable data under retention policy.

**Helper unavailable:** continue observation, remove automatic action availability and reconcile outstanding requests on return. Do not replace the helper with elevated free-form PowerShell.

**Model unavailable:** continue deterministic policies and evidence views; report analysis degradation.

**Feed stale:** show last successful refresh/source age; use cached data as stale context, not current intelligence.

**Excess resource use:** pause optional models, assessments and decoration first; verify bounded queues and process-tree accounting. Recovery remains prioritized.

**External policy conflict:** preserve external edits, report the conflict and offer a scoped reviewed reconciliation.

## Independent recovery

If local trust is questionable, preserve minimal evidence and use an independently obtained trusted recovery environment or vendor-supported recovery instructions. Firmware remediation is vendor/model-specific and must not run through a generic guessed command. Test real restoration of backups on authorized machines before advertising recoverability.

## Support intake

Collect version/build, capability status, operation IDs, exact error, selected redacted evidence and reproduction steps. Never request credentials or a complete private disk image as routine support. Redaction preview precedes external submission. Community support capacity and response times are commitments only after staffed approval.

## Routine maintenance

Review unresolved operations and coverage changes, dependency/update advisories, signing key lifecycle and known issues. Test recovery before major release/schema changes. Use the incident-response procedure for suspected product compromise rather than quietly pushing a new binary.

No service was restarted or host policy altered while authoring this runbook.
