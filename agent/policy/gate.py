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

        ``user_actions=True`` registers CLOSE_PROCESS for a human surface.
        That handler still requires Authorization.USER_APPROVED and a keep-on
        stamp from DualGate. A Cortex decision alone does not close a process.
        The Mission Console closes through the keep-on options card, which
        calls this same DualGate. There is no second mutate path.
        """
        registry = ActionRegistry()
        if user_actions:
            from agent.policy.handlers import close_process_handler

            registry.register(ActionKind.CLOSE_PROCESS, close_process_handler)
        return cls(
            cortex=PolicyCortex(store=store),  # persists issued L2+ decisions to the ledger
            executor=ActionExecutor(store, registry),
        )
