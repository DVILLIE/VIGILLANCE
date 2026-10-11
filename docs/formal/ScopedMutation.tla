-------------------------- MODULE ScopedMutation --------------------------
EXTENDS Naturals, FiniteSets
CONSTANT Grants
VARIABLES grant, journal, effect, applied, running, unsafeRemoval
vars == <<grant, journal, effect, applied, running, unsafeRemoval>>

Init == /\ grant = [g \in Grants |-> "available"]
        /\ journal = [g \in Grants |-> "none"]
        /\ effect = "absent"
        /\ applied = {}
        /\ running = TRUE
        /\ unsafeRemoval = FALSE

Unresolved == {g \in Grants : journal[g] \in {"intent", "unknown"}}

Claim(g) == /\ running /\ grant[g] = "available" /\ Unresolved = {}
            /\ grant' = [grant EXCEPT ![g] = "consumed"]
            /\ journal' = [journal EXCEPT ![g] = "intent"]
            /\ UNCHANGED <<effect, applied, running, unsafeRemoval>>

Revoke(g) == /\ grant[g] = "available"
             /\ grant' = [grant EXCEPT ![g] = "revoked"]
             /\ UNCHANGED <<journal, effect, applied, running, unsafeRemoval>>

Apply(g) == /\ running /\ journal[g] = "intent" /\ effect = "absent"
            /\ g \notin applied
            /\ effect' = g /\ applied' = applied \cup {g}
            /\ UNCHANGED <<grant, journal, running, unsafeRemoval>>

Record(g) == /\ running /\ journal[g] = "intent"
             /\ journal' = [journal EXCEPT ![g] = IF effect = g THEN "configuration_verified" ELSE "unknown"]
             /\ UNCHANGED <<grant, effect, applied, running, unsafeRemoval>>

ExternalEdit == /\ effect # "absent" /\ effect # "external"
                /\ effect' = "external"
                /\ UNCHANGED <<grant, journal, applied, running, unsafeRemoval>>

Crash == /\ running /\ running' = FALSE
         /\ UNCHANGED <<grant, journal, effect, applied, unsafeRemoval>>

Restart == /\ ~running /\ running' = TRUE
           /\ journal' = [g \in Grants |-> IF journal[g] = "intent" THEN "unknown" ELSE journal[g]]
           /\ UNCHANGED <<grant, effect, applied, unsafeRemoval>>

Restore(g) == /\ running
              /\ journal[g] \in {"intent", "unknown", "configuration_verified"}
              /\ journal' = [journal EXCEPT ![g] = IF effect \in {g, "absent"} THEN "restored" ELSE "unknown"]
              /\ effect' = IF effect = g THEN "absent" ELSE effect
              /\ UNCHANGED <<grant, applied, running, unsafeRemoval>>

Next == (\E g \in Grants : Claim(g) \/ Revoke(g) \/ Apply(g) \/ Record(g) \/ Restore(g))
        \/ ExternalEdit \/ Crash \/ Restart
Spec == Init /\ [][Next]_vars

TypeOK == /\ grant \in [Grants -> {"available", "consumed", "revoked"}]
          /\ journal \in [Grants -> {"none", "intent", "unknown", "configuration_verified", "restored"}]
          /\ effect \in Grants \cup {"absent", "external"}
          /\ applied \subseteq Grants /\ running \in BOOLEAN

AuthorizedEffects == \A g \in applied : grant[g] = "consumed"
DurableBeforeEffect == \A g \in applied : journal[g] # "none"
ExternalOwnershipPreserved == [][effect = "external" => effect' = "external"]_effect
NoOwnedEffectAfterRestore == \A g \in Grants : journal[g] = "restored" => effect # g
SerializedIntent == Cardinality({g \in Grants : journal[g] = "intent"}) <= 1
=============================================================================
