# IRAuth

IRAuth is a **Rust-first**, hardware-gated, Windows-Hello-style authentication
stack for Linux. It refuses to silently downgrade to an ordinary RGB webcam:
setup requires a Linux-visible IR/depth camera (or an explicitly verified USB
interface selector), binds Howdy to that exact strict device, and re-checks the binding on every
authentication ceremony.

The v0.1 recognition backend is **Howdy**. IRAuth wraps it in a Rust system
architecture so the recognition engine can later be replaced without changing
PAM, daemon IPC, diagnostics, hardware policy, or the public CLI.

## What is Rust

The IRAuth repository contains no Go source. These components are Rust:

- `irauthd` — hardened system daemon; verifies peer UID, camera policy and face checks.
- `pam_irauth.so` — native Rust PAM module with a deliberately small attack surface.
- `irauthctl` — setup, enrollment, hardware probing, status and diagnostics.
- `irauth-hardware` — strict V4L2/sysfs IR/depth hardware policy.
- `irauth-backend-howdy` — isolated Howdy adapter and configuration manager.
- `irauth-passkey` — Rust orchestration for TPM-backed WebAuthn/FIDO2 integration.

**One v0.1 exception:** the CTAP2/USB-IP transport itself is currently the pinned
third-party `howdy-as-passkey` bridge. That upstream bridge is written in Go.
IRAuth can **adopt an existing binary without Go**; a fresh `passkey install`
requires Go only to build that pinned external transport. Replacing it with a
native Rust CTAP2 implementation is tracked in `docs/ROADMAP.md`.

## Fedora quick start

If Howdy is already installed and configured, run:

```bash
sudo ./scripts/install.sh --configure --with-login
```

The installer builds the Rust workspace, installs the daemon/PAM module,
validates real IR hardware, repairs Howdy dlib assets when possible, binds Howdy
to the accepted IR camera, configures the face-only PAM backend, and prepares
TPM/USB-IP prerequisites. Group membership changes require one full logout/login.

For the machine that already has the TPM-backed `howdy-as-passkey` setup, use:

```bash
irauthctl passkey adopt
irauthctl passkey test
irauthctl doctor
```

That keeps the existing vault, TPM key and registered GitHub credential intact.
On a clean machine, `irauthctl passkey install` can build the pinned transport
instead.

The passkey authenticator is used in Chromium/Chrome/Brave through **Use your
security key**. Every ceremony flows through `pam_irauth.so` and a fresh IR face
check.

See `docs/ARCHITECTURE.md`, `docs/INSTALL-FEDORA.md`, `docs/PASSKEYS.md`, and
`SECURITY.md` before using IRAuth for an important account.
