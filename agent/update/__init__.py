"""Offline TUF verification. Privileged auto-update stays off."""

from agent.update.tuf import PRIVILEGED_AUTO_UPDATE, attestation_view, verify_update

__all__ = ["PRIVILEGED_AUTO_UPDATE", "attestation_view", "verify_update"]
