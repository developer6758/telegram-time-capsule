# Telegram Login service authentication

The service uses the configured HTTPS OpenID Connect issuer's discovery document,
JWKS and authorization-code flow. Configure an owned Telegram Login application,
its client ID and backend-held client secret, and the exact HTTPS
`/v1/auth/callback` URL registered with Telegram. The native app's MTProto login
keys, phone login codes and passwords are never used by this service.

Native requests:

1. Generate 32 random bytes and encode them with unpadded base64url as the
   `completion_verifier`. Hash the **raw bytes**, not the encoded string, with
   SHA-256 and base64url-encode the digest as `completion_challenge`.
2. POST `{ "completion_challenge": "..." }` to `/v1/auth/start`. The response has
   `transaction_id`, `authorization_url`, and `expires_ms`.
3. Open `authorization_url` in the system authorization browser. The service
   generates independent state, PKCE S256 and nonce values. The callback verifies
   the code, OIDC signature, issuer, audience, authorized party, expiry, issue time,
   nonce and the exact positive Telegram profile `id`. OIDC `sub` is retained as
   the provider subject and is never treated as the Telegram ID.
4. While that foreground login is active, POST `{ "transaction_id": "...",
   "completion_verifier": "..." }` to `/v1/auth/complete`. `409 login_pending`
   permits bounded foreground polling. A successful response contains
   `access_token`, `refresh_token`, `telegram_user_id`, `expires_ms`. Compare the
   verified ID with the selected native Telegram account before storing it.
5. Cancel the system authorization browser after the native request succeeds.
   The HTTPS callback returns success text; it never sends bearer tokens through
   a browser redirect or URL.

State, provider code and completion transactions are each one use. A wrong
completion proof does not consume a valid login. Token exchange failure requires
starting a new login. Transactions expire after ten minutes. Callback, transaction
and token bodies must stay out of HTTP/proxy/APM logs. The auth handlers emit no
request bodies or bearer values and return `Cache-Control: no-store`.

Access tokens expire after at most 15 minutes. Refresh rotates both tokens in the
same absolute 30-day session family. Using an already used refresh token revokes
that entire device session family, including recently rotated access tokens.
Concurrent requests serialize on the family row, so one accepted refresh followed
by reuse also revokes that family. Clients should serialize refresh operations.
`POST /v1/auth/logout` with the current bearer revokes that family and leaves other
devices signed in. PostgreSQL stores only SHA-256 token hashes.

No development identity header, test user parameter or test-auth endpoint is
compiled into the service. Automated tests use a TLS fake OIDC issuer only inside
Go `_test.go` files and temporary PostgreSQL schemas. This is not evidence of a
successful real Telegram Login. Production requires the owned credentials,
registered callback, trustworthy CA configuration and outbound issuer/JWKS access.

Auth transactions and old refresh hashes are retained to reject replay. Operational
cleanup may remove expired transactions and session families after their expiry;
removing a family cascades its expired access and refresh records. Do not delete
used refresh records from a live family, because that removes replay detection.
