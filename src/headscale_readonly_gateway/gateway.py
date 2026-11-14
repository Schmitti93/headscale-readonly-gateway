from __future__ import annotations

import argparse
import hmac
import http.server
import json
import logging
import os
import socket
import socketserver
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

ALLOWED_PATHS = frozenset({"/version", "/api/v1/node"})
MAX_LIMIT = 1_048_576
CHUNK_SIZE = 65_536
MAX_CONNECTIONS = 16


@dataclass(frozen=True)
class Config:
    bind: str
    port: int
    upstream: str
    cert: Path
    key: Path
    upstream_ca: Path | None
    upstream_api_key: str
    client_token: str
    max_response_bytes: int = MAX_LIMIT
    timeout_seconds: float = 10.0


def _read_secret(value: str | None, file_value: str | None, name: str) -> str:
    if bool(value) == bool(file_value):
        raise ValueError(f"set exactly one of {name} or {name}_FILE")
    secret = value if value else Path(file_value or "").read_text(encoding="utf-8").strip()
    if not secret or "\n" in secret or "\r" in secret:
        raise ValueError(f"{name} must be a non-empty single line")
    return secret


def validate_config(config: Config) -> None:
    parsed = urllib.parse.urlsplit(config.upstream)
    if parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.path not in ("", "/"):
        raise ValueError("upstream must be an origin without credentials, path, query, or fragment")
    if parsed.scheme == "http":
        if parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("HTTP upstream must be loopback")
    elif parsed.scheme == "https":
        if config.upstream_ca is not None:
            data = config.upstream_ca.read_bytes()
            if b"PRIVATE KEY" in data or b"BEGIN CERTIFICATE" not in data:
                raise ValueError("upstream CA certificate must contain certificates only")
            ssl.create_default_context(cafile=str(config.upstream_ca))
    else:
        raise ValueError("upstream must use loopback HTTP or HTTPS")
    if not parsed.hostname or parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid upstream")
    if not 0 <= config.port <= 65535:
        raise ValueError("invalid listen port")
    if not 1 <= config.max_response_bytes <= MAX_LIMIT:
        raise ValueError("max response bytes must be between 1 and 1048576")
    if not 0 < config.timeout_seconds <= 60:
        raise ValueError("timeout must be between 0 and 60 seconds")
    if hmac.compare_digest(config.upstream_api_key, config.client_token):
        raise ValueError("client token must differ from upstream API key")
    if not config.cert.is_file() or not config.key.is_file():
        raise ValueError("TLS certificate and key are mandatory")


class LimitedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._workers = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._workers.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._workers.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._workers.release()


class GatewayServer(LimitedThreadingMixIn, http.server.HTTPServer):
    request_queue_size = MAX_CONNECTIONS
    allow_reuse_address = False
    allowed_paths = ALLOWED_PATHS

    def __init__(self, config: Config) -> None:
        validate_config(config)
        self.config = config
        self.upstream = config.upstream.rstrip("/")
        self.allowed_paths = ALLOWED_PATHS
        self.upstream_context: ssl.SSLContext | None
        if urllib.parse.urlsplit(config.upstream).scheme == "https":
            self.upstream_context = ssl.create_default_context(
                cafile=str(config.upstream_ca) if config.upstream_ca else None
            )
        else:
            self.upstream_context = None
        super().__init__((config.bind, config.port), GatewayHandler)
        self.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.tls_context.load_cert_chain(config.cert, config.key)
        handlers: list[Any] = [urllib.request.ProxyHandler({}), NoRedirectHandler()]
        if self.upstream_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=self.upstream_context))
        self.upstream_opener = urllib.request.build_opener(*handlers)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        request, address = super().get_request()
        request.settimeout(self.config.timeout_seconds)
        return request, address

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            tls_request = self.tls_context.wrap_socket(request, server_side=True)
        except (OSError, ssl.SSLError, TimeoutError):
            request.close()
            self._workers.release()
            return
        super().process_request_thread(tls_request, client_address)

    def handle_error(self, request: Any, client_address: Any) -> None:
        logging.error("request handling failed")


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class GatewayHandler(http.server.BaseHTTPRequestHandler):
    server: GatewayServer
    server_version = "HeadscaleReadOnlyGateway/1"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        raw_path = getattr(self, "path", "").split("?", 1)[0]
        route = raw_path if raw_path in ALLOWED_PATHS or raw_path == "/health" else "<other>"
        method = getattr(self, "command", None)
        if not isinstance(method, str) or not method.isascii() or not method.isalpha():
            method = "<other>"
        status = args[1] if format == '"%s" %s %s' and len(args) > 1 else "-"
        logging.info(
            "request method=%s route=%s status=%s",
            method,
            route,
            status,
        )

    def _json(self, status: int, payload: dict[str, str]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def do_GET(self) -> None:
        path, separator, _query = self.path.partition("?")
        if separator:
            self._json(404, {"error": "not found"})
            return
        if path == "/health":
            self._json(200, {"status": "ok"})
            return
        if path not in self.server.allowed_paths:
            self._json(404, {"error": "not found"})
            return
        expected = f"Bearer {self.server.config.client_token}".encode()
        supplied = self.headers.get("Authorization", "").encode("utf-8", "surrogatepass")
        if not hmac.compare_digest(supplied, expected):
            self._json(401, {"error": "authentication required"})
            return
        # The scheme is restricted to HTTP/HTTPS by validate_config.
        req = urllib.request.Request(  # nosec B310
            self.server.upstream + path,
            headers={
                "Authorization": f"Bearer {self.server.config.upstream_api_key}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with self.server.upstream_opener.open(
                req,
                timeout=self.server.config.timeout_seconds,
            ) as response:
                length = response.headers.get("Content-Length")
                if length is not None and int(length) > self.server.config.max_response_bytes:
                    self._json(502, {"error": "upstream response too large"})
                    return
                body = _bounded_read(response, self.server.config.max_response_bytes)
                self.send_response(response.status)
                self.send_header(
                    "Content-Type", response.headers.get("Content-Type", "application/json").split(";", 1)[0]
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
        except ResponseTooLarge:
            self._json(502, {"error": "upstream response too large"})
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError):
            self._json(502, {"error": "upstream unavailable"})

    def _method_not_allowed(self) -> None:
        self._json(405, {"error": "method not allowed"})

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = do_CONNECT = do_TRACE = _method_not_allowed

    def __getattr__(self, name: str) -> Any:
        if name.startswith("do_"):
            return self._method_not_allowed
        raise AttributeError(name)


class ResponseTooLarge(Exception):
    pass


def _bounded_read(stream: BinaryIO, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(min(CHUNK_SIZE, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise ResponseTooLarge
        chunks.append(chunk)


def config_from_env() -> Config:
    env = os.environ
    return Config(
        bind=env.get("GATEWAY_BIND", "127.0.0.1"),
        port=int(env.get("GATEWAY_PORT", "8443")),
        upstream=env["HEADSCALE_UPSTREAM_URL"],
        cert=Path(env["GATEWAY_TLS_CERT_FILE"]),
        key=Path(env["GATEWAY_TLS_KEY_FILE"]),
        upstream_ca=Path(env["HEADSCALE_UPSTREAM_CA_FILE"]) if env.get("HEADSCALE_UPSTREAM_CA_FILE") else None,
        upstream_api_key=_read_secret(
            env.get("HEADSCALE_API_KEY"), env.get("HEADSCALE_API_KEY_FILE"), "HEADSCALE_API_KEY"
        ),
        client_token=_read_secret(
            env.get("GATEWAY_CLIENT_TOKEN"), env.get("GATEWAY_CLIENT_TOKEN_FILE"), "GATEWAY_CLIENT_TOKEN"
        ),
        max_response_bytes=int(env.get("GATEWAY_MAX_RESPONSE_BYTES", str(MAX_LIMIT))),
        timeout_seconds=float(env.get("GATEWAY_TIMEOUT_SECONDS", "10")),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        config = config_from_env()
        validate_config(config)
        if args.check_config:
            return 0
        with GatewayServer(config) as server:
            server.serve_forever()
    except (KeyError, ValueError, OSError, ssl.SSLError) as error:
        logging.error("configuration error: %s", error)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
