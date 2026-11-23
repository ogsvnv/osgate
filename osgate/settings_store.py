"""Safe, allowlisted, persisted operational parameters (never credentials)."""
EDITABLE = {
    'health_check_interval': (float, 1, 300),
    'health_check_timeout': (float, 0.5, 60),
    'health_failure_threshold': (int, 1, 20),
    'health_success_threshold': (int, 1, 20),
    'ssh_reconnect_initial_delay': (float, 0.2, 60),
    'ssh_reconnect_max_delay': (float, 1, 600),
    'socks_max_connections': (int, 1, 200000),
    'socks_idle_timeout': (float, 10, 86400),
    'traffic_retention_days': (int, 1, 365),
}

def validate_operational_values(raw):
    values = {}
    for name, (typ, low, high) in EDITABLE.items():
        if name not in raw:
            raise ValueError('Missing operational setting')
        v = typ(raw[name])
        if not low <= v <= high:
            raise ValueError('Invalid operational value')
        values[name] = v
    if values['ssh_reconnect_max_delay'] < values['ssh_reconnect_initial_delay']:
        raise ValueError('Reconnect max < initial')
    return values

def load_runtime_settings(db, cfg):
    for name, (typ, low, high) in EDITABLE.items():
        raw = db.get_setting(name)
        if not raw:
            continue
        try:
            value = typ(raw)
        except (TypeError, ValueError):
            continue
        if low <= value <= high:
            setattr(cfg, name, value)

def persist_runtime_settings(db, cfg, raw):
    values = validate_operational_values(raw)
    for name, value in values.items():
        db.set_setting(name, str(value))
        setattr(cfg, name, value)
    return values
