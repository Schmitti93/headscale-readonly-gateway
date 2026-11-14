from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def tls_files(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, Path]:
    directory = tmp_path_factory.mktemp("tls")
    key = directory / "server.key"
    cert = directory / "server.crt"
    ca = directory / "ca.crt"
    config = directory / "openssl.cnf"
    config.write_text(
        """[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n"""
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-config",
            str(config),
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    ca.write_bytes(cert.read_bytes())
    return cert, key, ca
