"""Docker checks HTTP application liveness, not external SSH/internet availability."""
import sys
from urllib.request import urlopen

def main():
    try:
        with urlopen(f'http://127.0.0.1:{__import__("os").getenv("WEB_PORT", "5812")}/healthz', timeout=5) as response:
            return 0 if response.status == 200 else 1
    except Exception:
        return 1

if __name__ == '__main__':
    sys.exit(main())
