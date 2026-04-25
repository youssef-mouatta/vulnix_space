"""Tier-based redaction of scan artifacts (applied at read time, not only at save)."""
from copy import deepcopy

_POC_UPGRADE_MSG = "Upgrade to Pro for PoC"


def apply_plan_limits(user_tier, issues):
    """
    Return a deep copy of issues with PoCs hidden for non-paid tiers.
    Pro and Business keep full PoCs so upgrades unlock historical reports.
    """
    out = deepcopy(issues)
    tier = (user_tier or "Free").strip().lower()
    if tier in ("pro", "business"):
        return out
    for item in out:
        if item.get("poc"):
            item["poc"] = _POC_UPGRADE_MSG
    return out
