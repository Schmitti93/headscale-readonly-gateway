# Headscale read-only gateway

A small, dependency-free Python HTTPS gateway that exposes exactly three routes:

| Method | Route | Authentication |
|---|---|---|
| `GET` | `/health` | none |
| `GET` | `/version` | client bearer token |
| `GET` | `/api/v1/node` | client bearer token |

Every other path returns `404`; every non-GET method returns `405`. The client token is independent from the upstream Headscale API key. Responses are buffered through a hard limit of at most 1 MiB, including chunked/unknown-length responses.

## Configuration

All configuration is environment-based. Secrets should use the `_FILE` forms; exactly one direct or file form must be set for each secret.

| Variable | Required | Default | Meaning |
|---|---:|---|---|
| `HEADSCALE_UPSTREAM_URL` | yes | — | Origin only. `http` is allowed only for `127.0.0.1`, `::1`, or `localhost`; otherwise verified `https` is required. No credentials/path/query/fragment. |
| `HEADSCALE_UPSTREAM_CA_FILE` | for private HTTPS CA | system trust | PEM CA certificate bundle. Private-key material is rejected. |
| `HEADSCALE_API_KEY` / `_FILE` | yes | — | Upstream Headscale bearer API key. |
| `GATEWAY_CLIENT_TOKEN` / `_FILE` | yes | — | Client bearer token; must differ from the API key. |
| `GATEWAY_TLS_CERT_FILE` | yes | — | PEM server certificate/chain. |
| `GATEWAY_TLS_KEY_FILE` | yes | — | Matching PEM server private key. |
| `GATEWAY_BIND` | no | `127.0.0.1` | Listen address. Set `0.0.0.0` explicitly for container port publishing. |
| `GATEWAY_PORT` | no | `8443` | Listen port. |
| `GATEWAY_MAX_RESPONSE_BYTES` | no | `1048576` | Hard response limit, range 1..1048576. |
| `GATEWAY_TIMEOUT_SECONDS` | no | `10` | Socket/upstream timeout, range >0..60. |

`--check-config` validates configuration and TLS material without listening. Logs contain only method, route without query, and status; tokens, upstream URLs, query strings, response bodies, client addresses, and topology are omitted.

## Build and run

```sh
docker build -t headscale-readonly-gateway:local .
docker compose up -d
```

The image runs as UID/GID 65532, has no runtime dependencies beyond Python, uses a digest-pinned base, and contains a healthcheck. The Compose example adds a read-only root filesystem, drops all capabilities, applies `no-new-privileges`, and mounts only configuration/secrets. Do not put real secrets in this repository.

For loopback HTTP, remember that a container's `127.0.0.1` is the container itself. Use host networking only where appropriate, or run Headscale in the same network namespace. HTTPS is the normal cross-container choice.

## Client

```sh
curl --fail --cacert ./ca.crt \
  -H "Authorization: Bearer $(cat ./client-token)" \
  https://gateway.example:8443/api/v1/node
```

## Development

```sh
python -m venv .venv
.venv/bin/pip install pytest==8.4.2 ruff==0.14.3 mypy==1.18.2 bandit==1.8.6 build==1.3.0
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/bandit -q -r src
```

The implementation was derived from the proven Ansible-managed gateway design, but this repository is standalone and does not modify or require that Ansible repository.
