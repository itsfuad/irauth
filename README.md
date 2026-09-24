# IRAuth

IRAuth is a hardware-gated, Windows-Hello-style authentication stack for Linux.
It refuses to silently downgrade to an ordinary RGB webcam: setup requires a
Linux-visible IR/depth camera (or an explicitly verified USB ID), and strict
setup requires TPM 2.0 for the passkey path.

The v0.1 recognition backend is **Howdy**. IRAuth wraps it in a Rust system
architecture so the recognition engine can later be replaced without changing
PAM, daemon IPC, diagnostics, hardware policy, or passkey integration.

## Components

- `irauthd` — privileged, hardened system daemon; serializes face checks.
- `pam_irauth.so` — small PAM module that asks `irauthd` to authenticate.
- `irauthctl` — setup, enrollment, hardware probing, status and diagnostics.
- `irauth-hardware` — strict V4L2/sysfs IR/depth hardware policy.
- `irauth-backend-howdy` — isolated Howdy adapter.
- `irauth-passkey` — TPM-backed WebAuthn/FIDO2 bridge integration.

## Fedora quick start

```bash
sudo ./scripts/install.sh --configure
```

The installer builds the Rust workspace, installs the daemon/PAM module,
validates IR hardware, repairs Howdy dlib assets when possible, configures the
face-only PAM backend, and prepares TPM/USB-IP prerequisites. Group membership
changes require one full logout/login. After logging back in:

```bash
irauthctl passkey install
irauthctl passkey start
irauthctl doctor
```

The passkey bridge is then usable in Chromium/Chrome/Brave via **Use your
security key**. Each WebAuthn ceremony is gated through `pam_irauth.so` and a
fresh IR face check.

See `docs/ARCHITECTURE.md`, `docs/INSTALL-FEDORA.md`, and `SECURITY.md` before
using IRAuth for an important account.
