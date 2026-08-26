"""Action hierarchy levels — Master Architecture §1.

0 Observe · 1 Explain · 2 Recommend (no mutation) · 3 Reversible · 4 Admin · 5 Emergency
"""

from __future__ import annotations

LEVEL_OBSERVE = 0
LEVEL_EXPLAIN = 1
LEVEL_RECOMMEND = 2
LEVEL_REVERSIBLE = 3
LEVEL_ADMIN = 4
LEVEL_EMERGENCY = 5

# Product defaults (not NIST-prescribed). Higher impact → higher floor.
CONFIDENCE_FLOOR: dict[int, float] = {
    LEVEL_OBSERVE: 0.0,
    LEVEL_EXPLAIN: 0.0,
    LEVEL_RECOMMEND: 0.50,
    LEVEL_REVERSIBLE: 0.75,
    LEVEL_ADMIN: 0.90,
    LEVEL_EMERGENCY: 0.97,
}
