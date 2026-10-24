# Remaining verification and operating dependencies

- Actual Telegram Login has not been exercised. Developer-owned Login credentials,
  registered exact HTTPS callback and outbound issuer/JWKS access are required.
  Passing a TLS fake OIDC test is not real Telegram authentication.
- No public service was deployed. Both modified iOS clients need the same reachable,
  trusted HTTPS service and pinned service signing public keys. No insecure TLS
  bypass or production test-auth mode exists.
- The iOS repository needs its official macOS/Xcode build and iPhone Simulator
  testing. Backend tests do not establish native integration, safe composer
  outbox recovery, visual quality, animation timing or two-client exchange.
- Native context checks reject forwarding/copying into a different chat. The
  service cannot independently verify Telegram delivery or message identity and
  treats client-reported Telegram IDs as advisory.
- PostgreSQL release/revoke transactions and process/database restart are tested
  locally; production crash recovery, encrypted backups, key rotation and restore
  need operator rehearsal. Live keys/ciphertext remain until explicit revocation;
  no background deletion fleet or production retention scheduler is included.
- Clock anomaly detection is operational and cannot detect an already wrong clock
  at startup. Real time-source monitoring remains required.
- Recipient manual opening is per device. Post-release disclosure and keys already
  delivered cannot be recalled. Stock-client deletion cannot guarantee revocation.
- Approximate layout and padding bucket disclose coarse length by design. Exact
  hidden text geometry across differing fonts/devices is impossible to guarantee.
- No Android, Desktop, Web, media/group/secret-chat implementation or promotional
  material is included.
