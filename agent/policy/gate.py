"""Runtime Policy Gate — Cortex + fail-closed ActionExecutor.

Handlers are intentionally empty at boot: no mutation is possible until a
future release explicitly registers typed handlers after verification exists.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent.policy.actions import ActionKind, ActionRegistry
from agent.policy.cortex import ActionExecutor, PolicyCortex
from agent.store.db import AgentStore


@dataclass
class PolicyGate:
    cortex: PolicyCortex
    executor: ActionExecutor

    @classmethod
    def create(cls, store: AgentStore, *, user_actions: bool = False) -> PolicyGate:
        """Build the policy gate.

        Default (``user_actions=False``): empty registry — the autonomous agent
        stays fail-closed and can perform NO mutation. This is the gate the
        headless nerve loop and the background controller use.

        ``user_actions=True`` is only for a human-driven surface (the Mission
        Console). It registers the single user-initiated CLOSE_PROCESS handler.
        That handler is still gated to Authorization.USER_APPROVED by the Cortex
        (see USER_APPROVED_ONLY), so it can never run without an explicit human
        confirm — there is no autonomous path to it.
        """
        registry = ActionRegistry()
        if user_actions:
            from agent.policy.handlers import close_process_handler

            registry.register(ActionKind.CLOSE_PROCESS, close_process_handler)
        return cls(
            cortex=PolicyCortex(store=store),  # persists issued L2+ decisions to the ledger
            executor=ActionExecutor(store, registry),
        )
