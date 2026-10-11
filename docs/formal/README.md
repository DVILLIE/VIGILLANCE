# D'Vielle — Scoped mutation safety model

This finite TLA+ specification describes two grants competing for one firewall resource. It separates durable claim, Windows effect, result recording and restoration so crashes can occur between those boundaries. An external edit changes ownership independently of the journal. Recovery preserves external ownership and records unknown outcomes rather than deleting foreign state. Expiry/revocation is abstracted as withdrawal of an available grant; consumed grants never become available again.

## Source correspondence

`Claim` models the BEGIN IMMEDIATE transaction in `GrantStore.claim`: grant consumption and operation intent commit together. `Apply` models the owned effect following the firewall journal intent in `apply_verified`. `Record` models result persistence. `Crash` and `Restart` retain effects and durable records without replay. `Restore` models the ownership/precondition guards in `remove_script` and the administrative recovery entry point. `ExternalEdit` abstracts any change which no longer satisfies the exact owned-state preconditions. `Revoke` includes expiry before a claim.

The resource is abstract, so the model does not encode Windows filter precedence, address parsing, executable leases, SQLite implementation, pipe authentication, cryptographic authorization or filesystem ACL behavior. These require separate source and actual runtime evidence. Successful model checking is mathematical evidence for this finite transition system, not actual Windows enforcement or a verified refinement proof.

## Safety claims

Every modeled applied grant is consumed and has durable intent. At most one in-flight intent exists. A restored operation owns no remaining modeled effect. A recovery transition never changes an external-owned effect. The model permits unresolved conflicts indefinitely; it does not assert automatic repair or availability under malicious external interference.

The temporal ownership property checks the actual effect transition, rather than relying on the diagnostic flag. Negative controls remove the external-ownership guard from `Restore` or grant-consumption from `Claim`: the relevant properties must then produce counterexamples. These changes belong in separate development copies, never production code.

The first model run found a counterexample to an overly strong proposed invariant, “at most one unresolved operation.” A previously verified operation can encounter an external conflict during recovery while a later intent exists; both records must be retained. The source permits this conservatively and blocks further mutation while either is pending. The corrected invariant checks serialized in-flight intent, without discarding or hiding legitimate recovery backlog. The initial failing trace is preserved in `TLC_SCOPED_MUTATION_INITIAL_2026-10-10.txt`; it is a model counterexample, not a measured Windows crash.

## Reproduction

Use the official TLA+ `tla2tools.jar` and a compatible Java runtime. Free portable development tools can be prepared with `scripts/prepare_formal_tools.py`; it checks the official Adoptium checksum and the GitHub release asset digest when published. Neither tool becomes an application runtime dependency or modifies the system PATH.

Run `java -Xmx256m -cp tla2tools.jar tlc2.TLC -workers 1 -config ScopedMutation.cfg ScopedMutation.tla` from this directory. Save the complete output and record artifact/source hashes. The current run result is recorded in the implementation evidence directory; this README alone does not assert success.

References: [official TLA+ tools](https://github.com/tlaplus/tlaplus), [TLC usage](https://docs.tlapl.us/using:tlc:start), [Adoptium API](https://github.com/adoptium/api.adoptium.net/blob/main/docs/cookbook.adoc).
