"""Runtime Policy Gate — Cortex + fail-closed ActionExecutor.

Handlers are intentionally empty at boot: no mutation is possible until a
future release explicitly registers typed handlers after verification exists.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent.policy.actions import ActionRegistry
from agent.policy.cortex import ActionExecutor, PolicyCortex
from agent.store.db import AgentStore


@dataclass
class PolicyGate:
    cortex: PolicyCortex
    executor: ActionExecutor

    @classmethod
    def create(cls, store: AgentStore) -> PolicyGate:
        """Build gate with empty registry (fail-closed mutations)."""
        return cls(
            cortex=PolicyCortex(),
            executor=ActionExecutor(store, ActionRegistry()),
        )
