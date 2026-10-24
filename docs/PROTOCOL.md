# Protocol v1

The machine-readable contract is `api/openapi.yaml` (JSON-formatted YAML,
OpenAPI 3.1). All JSON fields use snake_case; IDs are exact positive decimal
strings within signed 64-bit range. Binary fields are canonical unpadded base64url.
Requests reject duplicate keys, unknown fields, invalid UTF-8, trailing data,
excessive nesting and bodies over 100,000 bytes. TLS and service bearer sessions
are required for capsule operations.

Carrier (one ordinary native Telegram text message, at most 3,500 units):

```text
Time Capsule — requires a compatible client.
TCAP1.<kid>.<descriptor_b64url>.<signature_der_b64url>
```

`kid` and `service` are configured trust identifiers, never URLs from the message.
The iOS client verifies P-256/SHA-256 DER signature over the exact bytes
`TCAP-DESC-v1\0 || UTF8(kid) || 0x00 || descriptor`. Go signs the SHA-256 digest
once. The descriptor signs both participants, duration, immutable creation/deadline,
coarse layout and SHA-256 digests of the binding and `nonce || ciphertext || tag`.
No key, plaintext, text hash or word-level geometry appears in the carrier.

1. Authenticate with Telegram Login; the verified profile `id`, not OIDC `sub`,
   is the service principal. See `AUTH.md`.
2. Reserve with `recipient_id`, `duration_s` and `layout` under a durable
   `Idempotency-Key` (16–64 URL-safe characters). The service derives sender ID.
   Duration is 1–31,536,000 seconds. Layout contains v1 samples at constraints
   14, 20, 28 em, quarter-em dimensions, positive width within each constraint,
   positive height at most 512 em. The exact binding bytes contain v/service/
   capsule_id/sender_id/recipient_id/duration_s/layout and no deadline.
3. Generate a fresh AES-256 key and 12-byte nonce on the iPhone. JSON payload
   contains v1 exact text/entities. Prefix its UTF-8 byte length as unsigned
   4-byte big-endian; pad with random bytes to 512/1024/2048/4096/8192/16384/
   32768/65536 bytes. Encrypt AES-256-GCM with 16-byte tag and AAD
   `TCAP-PAYLOAD-v1\0 || binding_bytes`.
4. Seal with binding digest, nonce/ciphertext/tag/content_key. The service wraps
   the key with a separate 32-byte server key and fresh nonce. Wrapping AAD is
   `TCAP-WRAP-v1\0 || wrapping_kid || 0x00 || capsule_id`. Wrapped keys, wrapping
   key IDs and ciphertext persist in PostgreSQL. The service obtains a fresh
   database timestamp after blocking locks and commits `unlock_ms = created_ms +
   duration_s * 1000`. Identical retries preserve descriptor and deadline;
   changed requests conflict. Reservations expire after ten minutes.
5. Durably enqueue only the returned carrier through Telegram, without original
   entities, rich text, preview, quote, schedule or effect. Sealing is not proof
   of Telegram delivery. The native outbox owns recovery across this boundary.
6. Displaying zero changes only the UI to open padlock and `Tap to open`.
7. On explicit tap POST release with `open_operation_id` and `known_revision`.
   The service authenticates, locks capsule then participant, checks visibility/
   state, reads fresh `clock_timestamp()` after blocking locks, checks health and
   deadline, then unwraps. Both designated recipient and sender must wait.
   Early requests return 409 `not_ready` with unlock_ms and no key. Unknown and
   unauthorized capsules return 404. Revoked/hidden participant releases return
   410. Retried release rechecks current authorization; key-bearing responses
   are not stored in the idempotency table or HTTP caches.
8. Validate descriptor, message context, both digests, binding semantics and
   AEAD before rendering any plaintext. Cache locally using device-protected
   account-scoped encryption. A remote opened acknowledgement never opens a
   different device automatically.

`GET /v1/time` and all capsule responses supply server milliseconds. Client clock
samples affect countdown display only. No request field/header changes the
release clock. Local monotonic-vs-DB samples latch unhealthy on a detected jump
over two seconds; health and release then fail closed until operator recovery.
This is an operational guard, not proof against an administrator controlling time.

Revoke destroys live wrapped key/ciphertext/tag/nonce; a signed descriptor remains
as a tombstone. Hide affects only the caller. Release and revoke serialize on the
same capsule row. A release committed before revoke may already have delivered
the key and cannot be recalled. `opened` is advisory metadata, not authorization.

`testdata/ios-v1.json` is a deliberately public test-only Go interoperability
vector with Unicode, RTL, emoji and combining marks, SPKI DER and X9.63 public
key forms. It contains a known test key and must never be a deployed trust key.
Regenerate with `go run ./cmd/capsulefixture testdata/ios-v1.json`; ECDSA signature
bytes may vary while exact binding/payload bytes remain fixed. Tests verify
signature, AAD, ciphertext hashes, decrypt, UTF-8 text and bit mutations.
