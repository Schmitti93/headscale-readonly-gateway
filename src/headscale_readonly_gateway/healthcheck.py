from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.request


def main() -> int:
    port = int(os.environ.get("GATEWAY_PORT", "8443"))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(  # nosec B310: fixed loopback HTTPS URL
            f"https://127.0.0.1:{port}/health", context=context, timeout=3
        ) as response:
            return 0 if response.status == 200 and json.load(response) == {"status": "ok"} else 1
    except (OSError, ValueError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
