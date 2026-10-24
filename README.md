# Telegram Time Capsule — iOS release service

This repository implements the Go/PostgreSQL service used by the modified
`developer6758/Telegram-iOS` client. Telegram transports a signed, non-secret
`TCAP1` descriptor as an ordinary message; this service retains ciphertext and
an encrypted content key until its own PostgreSQL deadline. A compatible iOS
client retrieves the key only after an explicit open action.

The service is trusted with the key and can decrypt. This is **not end-to-end
encryption against the service**. Stock Telegram clients display the safe carrier
and cannot open it. Android, Desktop and Web implementations are out of scope.

Implemented: real Telegram Login OIDC code flow/PKCE, completion proof, opaque
sessions, rotating refresh, durable reserve/seal/idempotency, P-256 descriptors,
AES-GCM key wrapping, authorized delayed release, revoke/hide/opened metadata,
DB-clock health checks, bounded parsing/rate limits and an HTTPS executable.
No identity assertion header, production test-auth endpoint or clock override
exists. Real Telegram credentials and an owned HTTPS callback are required.

## Local setup

Requires Go 1.26+ and PostgreSQL 17 (or Docker Compose). Commands below are for a
POSIX shell, starting in this repository. Use your installed real Go compiler;
GNU Go, the board game sometimes installed as `/usr/bin/go`, is unrelated.

```sh
go mod download
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o bin/capsuled ./cmd/capsuled
CGO_ENABLED=0 go build -trimpath -o bin/capsulectl ./cmd/capsulectl
cp .env.example .env
./bin/capsulectl init-keys .local
```

Edit the ignored `.env` to set a random database password, persistent key paths,
your developer-owned Telegram Login client ID/secret and exact registered HTTPS
callback. Set `CAPSULE_DATABASE_URL` to match the password. Obtain a TLS certificate
trusted by both test iOS clients; put it at `.local/tls.crt` and its private key at
`.local/tls.key`. Supply the public signing key from `.local/public-trust.json`
to each iOS client's configured trust bundle. `init-keys` also creates
`.local/ios-configuration.json` with the exact iOS configuration field names and
standard-base64 DER public key. Set its owned HTTPS `base_url`, then copy it to
`Telegram/Telegram-iOS/Resources/TimeCapsuleConfiguration.json` in the iOS checkout.
The older `public-trust.json` uses base64url protocol encoding and is not directly
loadable as the iOS app resource. Never put private signing/wrapping
keys or the OIDC client secret into the app.

```sh
docker compose up -d postgres
set -a
. ./.env
set +a
./bin/capsuled migrate
./bin/capsuled
```

In a second shell, probe `https://YOUR_CERTIFICATE_HOST:8443/health/ready` using
normal CA verification (or `curl --cacert YOUR_DEVELOPMENT_CA ...` for your owned
trusted development CA). Do not use `-k`. PostgreSQL binds loopback on port 55432;
the service defaults to loopback TLS port 8443. A physical iPhone needs an
explicitly approved reachable HTTPS origin and registered callback; loopback on
this computer is not reachable from a phone. No service was deployed here.

Alternatively, after building the static `bin/capsuled`:

```sh
docker compose --profile service up -d --build
```

The service image runs unprivileged. Compose defaults its UID/GID to 1000 so
it can read the owner-only `.local` directory on a typical Linux checkout; set
`CAPSULE_CONTAINER_UID`/`CAPSULE_CONTAINER_GID` to your actual file owner if needed.
Keep file permissions restrictive. On managed networks, mount the current public
CA bundle read-only and set `SSL_CERT_FILE` for the service if an extra trusted CA
is required; never bake session-specific CA material into an image.

```sh
docker compose --profile service down
```

Do not add `-v` unless deliberately destroying the database. Preserve both the
PostgreSQL volume and `.local` keys across restarts and backups.

## Tests and native integration

```sh
CAPSULE_TEST_DATABASE_URL='postgres://USER:PASSWORD@127.0.0.1:55432/ISOLATED_TEST_DB?sslmode=disable' ./scripts/test.sh
```

Tests create and remove isolated PostgreSQL schemas; the configured test account
needs schema creation rights. They use a test-only TLS OIDC issuer in `_test.go`,
not real Telegram Login. [Build and test evidence](docs/BUILD_AND_TEST.md) records
executed commands and limits. [Authentication](docs/AUTH.md),
[wire protocol](docs/PROTOCOL.md), [OpenAPI](api/openapi.yaml),
[trust model](docs/THREAT_MODEL.md) and [known limitations](docs/KNOWN_LIMITATIONS.md)
describe the native contract and operating requirements.

The iOS client source must be built through its official Bazel/Make.py/Xcode
workflow on macOS. This Linux backend work does not establish an Xcode build,
Simulator run, real Telegram send, visual quality or competition readiness.
