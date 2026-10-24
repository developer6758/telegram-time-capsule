# Executed backend verification

The resumed implementation was verified on Linux x86_64 on 24 October 2026.
The source baseline was the initial backend commit
`43aa2ca95234d70ba18b918daa376124b40501fc`; all implementation changes remain
local. No service deployment or repository push occurred.

## Toolchain and isolated test environment

The system `/usr/bin/go` is GNU Go (the board game), so a real compiler was
downloaded to `/tmp/capsule-tools/go`. The executed compiler was
`go version go1.27.3 linux/amd64`. Its official Linux AMD64 archive was checked
against SHA-256
`65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`
from the Go download manifest. Dependencies are pinned in `go.mod`/`go.sum`.

Tests used PostgreSQL 17 in an isolated managed Docker container named
`time-capsule-pg-resume`, bound only to `127.0.0.1:55433`. The image was
`postgres:17-alpine@sha256:eee6c6e1b0894fa4fe0075eb054af9fd1cf39a35321c2d4110626cfe506411fb`.
The container used synthetic local test credentials. Each test creates and drops
its own schema. Do not point these tests at a production database.

## Commands and results

With the real Go compiler on PATH and `CAPSULE_TEST_DATABASE_URL` set to the
isolated PostgreSQL URL:

```sh
go test -race -count=1 -json ./... > /tmp/capsule-tests-final.json
go vet ./...
CGO_ENABLED=0 go build -trimpath -o /tmp/capsule-build/capsuled ./cmd/capsuled
CGO_ENABLED=0 go build -trimpath -o /tmp/capsule-build/capsulectl ./cmd/capsulectl
```

All four commands passed. The full suite passed **23 top-level tests/fuzz seed
groups**, with **57 pass events including subtests** and no failures. One
top-level test was intentionally skipped because it requires an external
PostgreSQL restart between separate invocations; both phases of that test were
then executed successfully as described below. The seed group is deterministic
seed execution, not a sustained fuzz campaign.

The final suite included:

- Protocol bounds, malformed/duplicate JSON, canonical identifiers/base64url,
  P-256 DER signatures, exact byte binding, AES-GCM wrapping and tamper rejection.
- Real PostgreSQL reserve/seal idempotency and immutable deadlines; sender and
  recipient early release denial; stranger denial; hide/revoke; no-store key
  responses; process reconstruction; release/revoke row-lock linearization;
  unhealthy clock rejection and malformed HTTP requests.
- OIDC signature/issuer/audience/expiry/nonce/issue-time/authorized-party and
  exact profile-ID checks; state/code/completion proof replay; expired completion;
  rotating refresh reuse and concurrent refresh revocation; device-scoped logout.
- A combined real TLS HTTP flow through OIDC authorization/PKCE, issued opaque
  sender/recipient/stranger sessions, reserve/seal, an early denied release,
  actual elapsed deadline, exact decrypted text, revoke and logout. Only the
  identity provider is a local test-only fixture; capsule requests use genuinely
  issued service bearer sessions, not an identity assertion header.
- `TestExecutableTLSStartup` builds and starts the actual `capsuled` executable
  with a temporary schema and local TLS OIDC discovery fixture. It verifies
  readiness/time through normal certificate trust, rejection of unauthenticated
  capsule access and rejection of cleartext HTTP. No TLS verification bypass is
  used. `TestGeneratedIOSConfigurationAndNoKeyOverwrite` verifies the exported
  iOS public-key encoding and refusal to overwrite an existing key directory.

`go vet` initially identified unkeyed external struct literals in the fixture
generator/test helpers. Those were changed to keyed literals, and the final vet
and builds passed. The executable-startup test initially used an uppercase
unquoted PostgreSQL search path; its isolated test schema was normalized to
lowercase, and the final executable test passed.

The persistent summary is [test-results.json](test-results.json). Temporary full
Go JSON output is `/tmp/capsule-tests-final.json` in this execution workspace;
temporary files are not expected to survive replacement of the environment.

## Actual database process restart

With the same isolated test DSN:

```sh
CAPSULE_DURABILITY_PHASE=prepare \
  CAPSULE_DURABILITY_FILE=/tmp/capsule-restart-fixture.json \
  go test -race -count=1 -run '^TestPostgresExternalRestart$' -v ./internal/server
docker restart time-capsule-pg-resume
CAPSULE_DURABILITY_PHASE=verify \
  CAPSULE_DURABILITY_FILE=/tmp/capsule-restart-fixture.json \
  go test -race -count=1 -run '^TestPostgresExternalRestart$' -v ./internal/server
```

Both phases passed. A real PostgreSQL container/process restart occurred between
them; the protected fixture retained the exact signing/wrapping keys and sealed
descriptor. Verification confirmed the original descriptor/deadline and permitted
release after that deadline. The verification phase dropped its schema and
removed its owner-only fixture. This tests database process restart, not disaster
recovery, encrypted backup restoration, physical disk loss or production key
rotation.

## Independent fixture verification

```sh
python3 tools/verify_fixture.py
```

Passed independent OpenSSL-backed signature verification, exact binding/payload
bytes, Unicode/RTL/emoji text, deterministic AES-256-GCM re-encryption, three
signature tamper cases and fifteen AEAD tamper cases. Python's `cryptography`
package is required. This independently verifies the Go fixture; it does not
execute CryptoKit or prove the Swift implementation has compiled.

The machine-readable OpenAPI 3.1 document parsed successfully as JSON-formatted
YAML, all local `$ref` entries resolved and all sixteen implemented paths were
present. Docker Compose and the distributable service image have not been
launched as a complete deployed stack here; the tested executable was run
directly against isolated PostgreSQL with the local TLS issuer fixture.

## External/native verification still required

Real Telegram Login was **not** exercised. Tests use a TLS fake issuer defined
only in test sources. Developer-owned Telegram Login credentials, an approved
reachable HTTPS callback/origin, trusted certificates and two controlled Telegram
accounts remain required. No iOS build, XCTest, iPhone Simulator run, native
two-client message exchange, animation recording or device performance
measurement was performed by these backend tests. Follow the companion iOS
checkout's official Make.py/Bazel/Xcode workflow before independent testing or
competition submission.
