"""Deterministic candidate selection. Never uses a local network path."""
import itertools
import time

MODES = {'failover', 'round_robin', 'weighted_round_robin', 'manual', 'sticky'}


class Router:
    def __init__(self):
        self._round = itertools.count()
        self._sticky = {}
        self._selected_failover_id = None
        self._failover_since = 0.0
        self.last_failover = None

    def candidates(self, servers: list[dict], settings: dict, client: dict) -> list[dict]:
        ready = sorted((x for x in servers if x['ready']),
                       key=lambda x: (x['priority'], x['id']))
        pinned = client.get('pinned_server_id')
        if pinned is not None:
            primary = [x for x in ready if x['id'] == pinned]
            if not client.get('allow_fallback'):
                return primary
            return primary + [x for x in ready if x['id'] != pinned]
        mode = settings.get('mode', 'failover')
        if mode == 'manual':
            return [x for x in ready if x['id'] == settings.get('manual_server_id')]
        if not ready:
            return []
        if mode == 'failover':
            chosen = ready[0]
            if self._selected_failover_id is not None:
                previous = next((s for s in ready if s['id'] == self._selected_failover_id), None)
                if previous and previous['id'] != chosen['id']:
                    elapsed = time.monotonic() - self._failover_since
                    if not settings.get('auto_failback', True) or elapsed < settings.get('failback_delay', 0):
                        chosen = previous
            if self._selected_failover_id != chosen['id']:
                if self._selected_failover_id is not None:
                    self.last_failover = time.time()
                self._selected_failover_id = chosen['id']
                self._failover_since = time.monotonic()
            return [chosen] + [s for s in ready if s['id'] != chosen['id']]
        if mode == 'round_robin':
            n = next(self._round) % len(ready)
            return ready[n:] + ready[:n]
        if mode == 'weighted_round_robin':
            # Smooth weighted RR for first choice, then deterministic failover order.
            total = sum(max(1, x['weight']) for x in ready)
            position = next(self._round) % total
            chosen = ready[-1]
            for x in ready:
                position -= max(1, x['weight'])
                if position < 0:
                    chosen = x
                    break
            return [chosen] + [x for x in ready if x is not chosen]
        if mode == 'sticky':
            key = client['id']
            target = self._sticky.get(key)
            if target not in {x['id'] for x in ready}:
                target = ready[0]['id']
                self._sticky[key] = target
            return [x for x in ready if x['id'] == target] + [x for x in ready if x['id'] != target]
        return ready
