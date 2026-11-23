"""Bounded routing event tracking; never log each SOCKS5 connection.

Only successful global route selection changes are journaled. Round-robin
and client-pinned routes are intentionally excluded from global transitions.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


class RouteHistoryTracker:
    def __init__(self, db):
        self.db = db
        self._last_id: int | None = None
        self._last_mode: str | None = None
        self._pending_id: int | None = None
        self._pending_count = 0

    def reset(self):
        self._last_id = None
        self._last_mode = None
        self._pending_id = None
        self._pending_count = 0

    def observe(self, *, mode: str, selected: int, available: list[dict],
                preferred_id: int | None = None):
        """Report a real selected route; use three observations for RTT changes.

        Called after a successful SSH channel open for an unpinned client.
        Failing to save an event must never affect SOCKS forwarding.
        """
        if mode not in ('failover', 'min_rtt', 'manual'):
            self.reset()
            return
        if mode != self._last_mode:
            self.reset()
            self._last_mode = mode
        if self._last_id is None:
            self._last_id = selected
            return
        if selected == self._last_id:
            self._pending_id = None
            self._pending_count = 0
            return
        if mode == 'min_rtt':
            if self._pending_id != selected:
                self._pending_id = selected
                self._pending_count = 1
            else:
                self._pending_count += 1
            if self._pending_count < 3:
                return
        previous = next((x for x in available if x['id'] == self._last_id), None)
        new = next((x for x in available if x['id'] == selected), None)
        if previous is None or not previous.get('ready'):
            reason = 'offline'
        elif preferred_id is not None and preferred_id != selected:
            reason = 'forwarding_failed'
        elif mode == 'min_rtt':
            reason = 'lower_rtt'
        elif mode == 'manual':
            reason = 'manual'
        elif previous['priority'] > (new or {}).get('priority', previous['priority']):
            reason = 'recovered'
        else:
            reason = 'route_changed'
        details = {'old_rtt_ms': previous.get('latency_ms') if previous else None,
                   'new_rtt_ms': new.get('latency_ms') if new else None,
                   'previous_ready': previous.get('ready') if previous else False,
                   'previous_error': previous.get('last_error') if previous else None}
        try:
            self.db.record_route_event(
                from_server_id=self._last_id, to_server_id=selected,
                reason=reason, mode=mode, actor='system', details=details)
        except Exception:
            log.warning('Route event could not be persisted')
        self._last_id = selected
        self._pending_id = None
        self._pending_count = 0
