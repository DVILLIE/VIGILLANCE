# D'Vielle — Data Model, IPC and Integration Contracts

Version 1.0 • 10 October 2026 • Proposed interface specification

## Data entities

**EvidenceEvent:** schema_version; event_id; collector_id/version; host_id; boot_id where available; observed_at_utc; ingested_at_utc; monotonic sequence; target identity; event type; minimal facts; provenance references; collection errors; sensor health. Preserve original timestamps with their semantics. Local clocks may drift; age assessments must record clock uncertainty.

**TargetIdentity:** canonical local path when applicable; file identity/hash where acquired; signer result; PID plus process creation time and boot identity; user/session identity; resolved address/port/protocol for communication. A PID or filename alone is insufficient.

**Finding:** finding_id; evidence references; affected asset; hypothesis; known benign alternatives; applicability state; confidence provenance/calibration version; proposed control; coverage gaps; expiry/review state. Unknown applicability remains explicit.

**Authorization:** authorization_id; issuing authority; operation; exact scope; policy_version; decision time; valid interval; revocation state; request binding; permitted recovery semantics. A request supplied by an unprivileged client cannot issue its own authorization.

**Operation:** operation_id; authorization reference; resource claim; target identity; preconditions; prior state/digest; desired state; owned artifacts; lifecycle state; timestamps; verification evidence; recovery result.

**AssessmentScope:** authority record; asset allowlist; address/domain rules; exclusions; approved test classes; rate limits; schedule; redirect/DNS handling; stop conditions; export policy.

These are proposed entities, not a claim that the existing database already implements them.

## Proposed IPC envelope

A versioned request carries protocol_version, request_id, operation_id, operation, typed params, authorization reference and evidence references. The OS-derived caller identity is added by the server; a caller-supplied SID is never authoritative. Frame size, nesting depth, list length, string length and connection timeout are bounded before parsing or dispatch.

Reject unsupported protocol versions and unknown fields when they could alter meaning. Responses carry status, error code, operation_id, actual lifecycle state and verification references. “Accepted” means accepted for processing, not protection verified.

The current contract version is 1 and defines restrict_network with program, profile, address_families and remote_addresses. New fields or process-instance semantics require explicit protocol/version review. Preserve the existing safety validation; do not silently relax path or address restrictions to match this proposed envelope.

## Idempotency and replay

Duplicate operation IDs retrieve a recorded outcome when request content matches. Mismatched content under an existing ID is rejected. A crash with unknown outcome triggers reconciliation, not replay. Expired authorization cannot initiate new mutation; recovery follows protected ownership policy separately.

A client timestamp or nonce alone does not prevent replay. Bind authorization to scope, operation and current protected server policy. Avoid shared credentials in broadly writable settings.

## Persistence and integrity

Use transactional records for intent and lifecycle transitions. Document durability guarantees of the selected storage engine and crash behavior on Windows. Preserve unresolved intent through migrations. Backup/export and deletion must handle journals, database auxiliary files and diagnostics coherently.

Hashes can help detect accidental mismatch but do not make a locally writable log authentic against an attacker who can rewrite both content and hash. Protected storage or signed remote receipts require their own threat model and privacy review.

## Adapter contract

Each adapter declares version, supported OS/build prerequisites, required privilege, observations/actions, operation schema, scope semantics, preconditions, postconditions, cancellation, ownership and recovery. Intelligence adapters additionally declare upstream licensing, freshness, retry/backoff and payload limits.

External APIs are optional enrichment. The collector never uploads user documents automatically. Cache failures do not become healthy evidence. EPSS is lookup enrichment; bulk refresh uses its daily CSV as advised by FIRST. Package/version observations passed to OSV may disclose inventory and require the approved data policy.

## Export

Export a manifest identifying schema, application/source version, selected record range, redaction choices and integrity hash. Keep observation and inference distinguishable. Include gaps and failed/unknown actions. Export is user-initiated and reviewed before external sharing. No fabricated example events are included in this contract.
