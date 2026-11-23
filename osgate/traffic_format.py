"""Compact, human-readable traffic volume for OSGate overview cards."""

def human_bytes(value: int) -> str:
    """Use 1024-based units and Russian decimal comma."""
    try:
        number = max(0, int(value))
    except (ValueError, TypeError, OverflowError):
        return '—'
    if number < 1024:
        return f'{number} Б'
    for factor, unit in ((1024**4, 'ТБ'), (1024**3, 'ГБ'),
                         (1024**2, 'МБ'), (1024, 'КБ')):
        if number >= factor:
            value = number / factor
            decimals = 1 if value < 100 else 0
            return f'{value:.{decimals}f}'.replace('.', ',') + ' ' + unit
    return f'{number} Б'


def human_uptime(seconds: int) -> str:
    """Readable Russian duration with days/hours/minutes, seconds if short."""
    try:
        remaining = max(0, int(seconds))
    except (ValueError, TypeError, OverflowError):
        return '—'
    days, remaining = divmod(remaining, 86400)
    hours, remaining = divmod(remaining, 3600)
    minutes, secs = divmod(remaining, 60)
    parts = []
    if days:
        parts.append(f'{days} дн.')
    if hours:
        parts.append(f'{hours} ч')
    if minutes:
        parts.append(f'{minutes} мин')
    if not parts:
        return f'{secs} сек'
    if not days and not hours:
        parts.append(f'{secs} сек')
    return ' '.join(parts)
