from __future__ import annotations

import contextlib
import http.server
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from headscale_readonly_gateway.gateway import Config, GatewayServer, validate_config


class MockUpstream(http.server.ThreadingHTTPServer):
    api_key = "upstream-secret"


class MockHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        if self.headers.get("Authorization") != f"Bearer {self.server.api_key}":  # type: ignore[attr-defined]
            self.send_error(401)
            return
        if self.path == "/oversized":
            body = b"x" * 2049
        else:
            body = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        # Deliberately omit Content-Length for the oversized stream.
        if self.path != "/oversized":
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", f"http://127.0.0.1:{self.server.target_port}/stolen")  # type: ignore[attr-defined]
        self.end_headers()


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    seen = False

    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        type(self).seen = True
        self.send_response(200)
        self.end_headers()


@contextlib.contextmanager
def running(server: http.server.HTTPServer):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def request(url: str, cafile: Path, token: str | None = None, method: str = "GET"):
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    req = urllib.request.Request(url, headers=headers, method=method)
    return urllib.request.urlopen(req, context=ssl.create_default_context(cafile=str(cafile)), timeout=3)


def make_gateway(tmp_path: Path, upstream: str, tls_files: tuple[Path, Path, Path]) -> GatewayServer:
    cert, key, _ca = tls_files
    cfg = Config("127.0.0.1", 0, upstream, cert, key, None, "upstream-secret", "client-secret", 1024, 2.0)
    return GatewayServer(cfg)


def test_validate_accepts_loopback_http_and_https(tmp_path: Path, tls_files: tuple[Path, Path, Path]) -> None:
    cert, key, ca = tls_files
    validate_config(Config("127.0.0.1", 8443, "http://127.0.0.1:8080", cert, key, None, "a", "b", 1024, 2))
    validate_config(Config("127.0.0.1", 8443, "https://headscale.example", cert, key, ca, "a", "b", 1024, 2))


@pytest.mark.parametrize(
    "url",
    [
        "http://headscale.example:8080",
        "http://0.0.0.0:8080",
        "https://user:pass@example.com",
        "https://example.com/base",
        "ftp://example.com",
    ],
)
def test_validate_rejects_unsafe_upstream(url: str, tls_files: tuple[Path, Path, Path]) -> None:
    cert, key, ca = tls_files
    with pytest.raises(ValueError):
        validate_config(Config("127.0.0.1", 8443, url, cert, key, ca, "a", "b", 1024, 2))


def test_validate_rejects_private_key_as_ca(tmp_path: Path, tls_files: tuple[Path, Path, Path]) -> None:
    cert, key, _ca = tls_files
    with pytest.raises(ValueError, match="CA certificate"):
        validate_config(Config("127.0.0.1", 8443, "https://example.com", cert, key, key, "a", "b", 1024, 2))


def test_gateway_policy_and_proxy(tmp_path: Path, tls_files: tuple[Path, Path, Path]) -> None:
    _cert, _key, ca = tls_files
    upstream = MockUpstream(("127.0.0.1", 0), MockHandler)
    with running(upstream):
        gateway = make_gateway(tmp_path, f"http://127.0.0.1:{upstream.server_port}", tls_files)
        with running(gateway):
            base = f"https://127.0.0.1:{gateway.server_port}"
            with request(base + "/health", ca) as response:
                assert response.status == 200
            with request(base + "/version", ca, "client-secret") as response:
                assert json.load(response) == {"path": "/version"}
            with request(base + "/api/v1/node", ca, "client-secret") as response:
                assert json.load(response) == {"path": "/api/v1/node"}
            for path, token, status in [("/version", None, 401), ("/nope", "client-secret", 404)]:
                with pytest.raises(urllib.error.HTTPError) as error:
                    request(base + path, ca, token)
                assert error.value.code == status
            with pytest.raises(urllib.error.HTTPError) as error:
                request(base + "/api/v1/node", ca, "client-secret", "POST")
            assert error.value.code == 405


def test_oversized_stream_is_rejected_without_content_length(
    tmp_path: Path, tls_files: tuple[Path, Path, Path]
) -> None:
    _cert, _key, ca = tls_files
    upstream = MockUpstream(("127.0.0.1", 0), MockHandler)
    with running(upstream):
        gateway = make_gateway(tmp_path, f"http://127.0.0.1:{upstream.server_port}", tls_files)
        gateway.allowed_paths = frozenset({"/oversized"})
        with running(gateway):
            with pytest.raises(urllib.error.HTTPError) as error:
                request(f"https://127.0.0.1:{gateway.server_port}/oversized", ca, "client-secret")
            assert error.value.code == 502


def test_https_upstream_certificate_is_verified(tmp_path: Path, tls_files: tuple[Path, Path, Path]) -> None:
    cert, key, ca = tls_files
    upstream = MockUpstream(("127.0.0.1", 0), MockHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    upstream.socket = context.wrap_socket(upstream.socket, server_side=True)
    with running(upstream):
        cfg = Config(
            "127.0.0.1",
            0,
            f"https://127.0.0.1:{upstream.server_port}",
            cert,
            key,
            ca,
            "upstream-secret",
            "client-secret",
            1024,
            2,
        )
        gateway = GatewayServer(cfg)
        with running(gateway):
            with request(f"https://127.0.0.1:{gateway.server_port}/version", ca, "client-secret") as response:
                assert response.status == 200


def test_upstream_redirect_is_not_followed(tmp_path: Path, tls_files: tuple[Path, Path, Path]) -> None:
    _cert, _key, ca = tls_files
    target = MockUpstream(("127.0.0.1", 0), CaptureHandler)
    upstream = MockUpstream(("127.0.0.1", 0), RedirectHandler)
    upstream.target_port = target.server_port  # type: ignore[attr-defined]
    CaptureHandler.seen = False
    with running(target), running(upstream):
        gateway = make_gateway(tmp_path, f"http://127.0.0.1:{upstream.server_port}", tls_files)
        with running(gateway):
            with pytest.raises(urllib.error.HTTPError) as error:
                request(f"https://127.0.0.1:{gateway.server_port}/version", ca, "client-secret")
            assert error.value.code == 502
            assert CaptureHandler.seen is False


def test_arbitrary_non_get_method_returns_405(tmp_path: Path, tls_files: tuple[Path, Path, Path]) -> None:
    _cert, _key, ca = tls_files
    upstream = MockUpstream(("127.0.0.1", 0), MockHandler)
    with running(upstream):
        gateway = make_gateway(tmp_path, f"http://127.0.0.1:{upstream.server_port}", tls_files)
        with running(gateway):
            with pytest.raises(urllib.error.HTTPError) as error:
                request(f"https://127.0.0.1:{gateway.server_port}/version", ca, method="BREW")
            assert error.value.code == 405


def test_failed_tls_handshakes_do_not_exhaust_workers(tmp_path: Path, tls_files: tuple[Path, Path, Path]) -> None:
    _cert, _key, ca = tls_files
    upstream = MockUpstream(("127.0.0.1", 0), MockHandler)
    with running(upstream):
        gateway = make_gateway(tmp_path, f"http://127.0.0.1:{upstream.server_port}", tls_files)
        with running(gateway):
            for _ in range(20):
                with socket.create_connection(("127.0.0.1", gateway.server_port), timeout=1) as connection:
                    connection.sendall(b"not tls")
                time.sleep(0.02)
            with request(f"https://127.0.0.1:{gateway.server_port}/health", ca) as response:
                assert response.status == 200
