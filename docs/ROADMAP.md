# Roadmap

IRAuth intentionally separates integration/security policy from recognition and
transport implementations. The v0.1 goal is to make the Linux IR authentication
stack deterministic, diagnosable and difficult to misconfigure.

## v0.1 — system integration foundation

- Rust daemon, CLI and PAM module.
- Strict IR/depth hardware policy with no RGB fallback.
- Per-ceremony verification that Howdy is still bound to the accepted IR node.
- Howdy backend with dlib asset repair and bounded authentication time.
- TPM/USB-IP setup and diagnostics.
- Adoption of existing TPM-backed passkey vaults without changing credentials.
- Pinned external CTAP2 transport for WebAuthn compatibility.

## v0.2 — native Rust passkey transport

Replace the pinned external `howdy-as-passkey` executable with an IRAuth-owned
Rust CTAP2/USB-IP implementation. The security contract remains the same:
`pam_irauth.so`/`irauthd` performs fresh verification and private passkey keys
remain TPM-bound.

This step should not be merged until interoperability tests cover Chromium,
Firefox (where supported), GitHub/WebAuthn test sites, suspend/resume, malformed
CTAP traffic and TPM recovery behavior.

## Later — native biometric backend

Introduce a pluggable Rust-facing IR recognition/liveness backend so Howdy can
become optional. IRAuth will not claim Windows Hello equivalence merely because
an IR stream exists: camera authenticity, anti-spoofing/liveness quality,
model/template protection and secure-path limitations must be documented and
tested separately.
