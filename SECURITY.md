# Security policy

## Supported versions

Security fixes are applied to the latest release on `main`.

## Reporting

Report vulnerabilities privately through GitHub's private vulnerability reporting for this repository. Do not open a public issue containing secrets, exploit details, network topology, certificates, or tokens.

## Security model

- Inbound TLS certificate and key are mandatory; TLS 1.2 is the minimum.
- Only authenticated `GET /version` and `GET /api/v1/node` are proxied. `GET /health` is unauthenticated.
- The gateway client token must be different from the Headscale API key.
- Plain HTTP upstreams must resolve syntactically to loopback names/addresses; non-loopback upstreams require HTTPS certificate verification.
- Upstream responses are read in bounded chunks and rejected above the configured limit (maximum 1 MiB), even without `Content-Length`.
- Requests and upstream operations use finite timeouts.
- Logs deliberately exclude authorization headers, URLs, queries, bodies, client IPs, and topology.

The gateway does not replace network policy. Restrict ingress to intended clients and restrict egress to the Headscale origin. Mount secrets read-only, rotate both tokens independently, and use a read-only filesystem with all Linux capabilities dropped.
