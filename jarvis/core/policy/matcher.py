from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Callable, List, Optional, Set

from zoneinfo import ZoneInfo

from jarvis.core.policy.models import PolicyContext, PolicyMatch, TimeWindow


_DOW = {"MON": 0, "TUE": 1, "WED": 2, "THU": 3, "FRI": 4, "SAT": 5, "SUN": 6}


def _parse_hhmm(s: str) -> tuple[int, int]:
    parts = str(s).split(":")
    if len(parts) != 2:
        raise ValueError("HH:MM expected")
    return int(parts[0]), int(parts[1])


def _in_time_window(now: dt.datetime, tw: TimeWindow) -> bool:
    tz = ZoneInfo(str(tw.timezone or "UTC"))
    local = now.astimezone(tz)
    sh, sm = _parse_hhmm(tw.start)
    eh, em = _parse_hhmm(tw.end)
    start = local.replace(hour=sh, minute=sm, second=0, microsecond=0)
    end = local.replace(hour=eh, minute=em, second=0, microsecond=0)
    if start <= end:
        return start <= local <= end
    # crosses midnight
    return local >= start or local <= end


@dataclass
class PolicyMatcher:
    now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc)

    def matches(self, ctx: PolicyContext, m: PolicyMatch) -> bool:
        # intent id include/exclude
        if m.intent_id_in is not None and ctx.intent_id not in set(m.intent_id_in):
            return False
        if m.intent_id_not_in is not None and ctx.intent_id in set(m.intent_id_not_in):
            return False

        req = set(ctx.required_capabilities or [])

        if m.capabilities_all is not None and not set(m.capabilities_all).issubset(req):
            return False
        if m.capabilities_any is not None and not (req.intersection(set(m.capabilities_any))):
            return False
        if m.capabilities_not is not None and req.intersection(set(m.capabilities_not)):
            return False

        # source
        src = str(ctx.source or "cli")
        if m.source_in is not None and src not in set(m.source_in):
            return False
        if m.source_not_in is not None and src in set(m.source_not_in):
            return False

        # bools
        if m.is_admin is not None and bool(ctx.is_admin) is not bool(m.is_admin):
            return False
        if m.safe_mode is not None and bool(ctx.safe_mode) is not bool(m.safe_mode):
            return False
        if m.shutting_down is not None and bool(ctx.shutting_down) is not bool(m.shutting_down):
            return False

        if m.secure_store_status_in is not None:
            if (ctx.secure_store_mode or "") not in set(m.secure_store_status_in):
                return False

        if m.resource_over_budget is not None:
            if ctx.resource_over_budget is None:
                return False
            if bool(ctx.resource_over_budget) is not bool(m.resource_over_budget):
                return False

        if m.rate_limited is not None:
            if ctx.rate_limited is None:
                return False
            if bool(ctx.rate_limited) is not bool(m.rate_limited):
                return False

        if m.time_window is not None:
            try:
                if not _in_time_window(self.now(), m.time_window):
                    return False
            except Exception:
                # if time window invalid, fail safe: no match
                return False

        if m.day_of_week_in is not None:
            want = set()
            for d in m.day_of_week_in:
                want.add(_DOW.get(str(d).strip().upper(), -1))
            if self.now().weekday() not in want:
                return False

        tags = set(ctx.tags or [])
        if m.tags_all is not None and not set(m.tags_all).issubset(tags):
            return False
        if m.tags_any is not None and not tags.intersection(set(m.tags_any)):
            return False

        # IP allow/deny lists (exact match)
        if m.client_ip_in is not None:
            if not ctx.client_ip or ctx.client_ip not in set(m.client_ip_in):
                return False
        if m.client_ip_not_in is not None:
            if ctx.client_ip and ctx.client_ip in set(m.client_ip_not_in):
                return False

        return True

