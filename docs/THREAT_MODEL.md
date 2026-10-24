# Trust and protection boundary

Protected: a designated recipient, alternate account, carrier inspector or modified
client cannot obtain the escrow key before the honest service's PostgreSQL
deadline. The service derives participants from verified Telegram Login profiles;
claiming a user ID in an HTTP header/body does not authenticate. Descriptor
signature and AEAD bind identity, layout, duration and content. Client clock
changes cannot authorize release. Hidden/tampered/unknown data fails closed.

Trusted: release service, PostgreSQL and its clock, signing/wrapping key operators,
TLS trust, Telegram Login issuer/JWKS, and native key generation/protected cache.
The service holds ciphertext and can unwrap the key; it can decrypt at any time.
This is not end-to-end encryption against that service and has not received an
independent security audit. OIDC login is separate from native MTProto login;
no Telegram session auth key or phone-login secret is sent to the service.

Excluded guarantees: compromised service/operator/clock, stolen sender plaintext,
compromised unlocked iPhone, compromised recipient Login session, disclosure after
release and screenshots. A service cannot prove a physical human tap after the
deadline; that is the honest iOS UX contract. Approximate text geometry and padded
ciphertext size intentionally leak coarse content length. Telegram may already
have received an ordinary composer cloud draft before capsule mode was chosen.

Rows serialize release/revoke; revocation cannot recall an earlier authorized
response, offline cached keys, screenshots or copies. Deletion in an unmodified
Telegram client cannot reliably inform this service. Native modified-client
backend-first revoke/hide is required. Telegram and this service have no atomic
shared transaction, so durable native outbox reconciliation is essential.

Operational controls: HTTPS only in capsuled; request/body/rate bounds; no request
body/token/key logging; no-store responses; hashed access/refresh tokens; one-use
state/code/completion transactions; key wrapping at rest; persistent key IDs and
rotation keyring. Database plaintext-key responses are never cached. A root
administrator can still inspect process memory. Go buffer clearing is best effort,
not a claim of reliable managed-memory erasure.

Retain all sealed capsules until explicit revoke. Unsealed reservations become
unusable at ten minutes; expired auth/session data may be purged after expiry,
except used refresh hashes in live families must remain for replay detection.
Production capacity, backup expiry and audited retention are operator decisions
that must be documented before public operation. Back up encrypted data and key
material separately with controlled access; destroying either can destroy capsule
availability. Old wrapping/signing public keys must remain available for existing
capsules. Readiness rejects missing wrapping keys still referenced by live rows.

Clock health compares observed PostgreSQL milliseconds with monotonic process
elapsed time and latches failures on jumps over two seconds. It cannot detect a
clock already wrong at process start or a malicious administrator. Use trustworthy
host time synchronization and independent operational monitoring. Recover from a
clock alarm only after verifying the host/database clock; a blind restart is not
a safety procedure.
