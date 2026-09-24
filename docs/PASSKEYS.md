# Passkeys

IRAuth's orchestration and security gate are Rust. In v0.1 the low-level
CTAP2/USB-IP transport deliberately reuses
[`NicklasKleemann/howdy-as-passkey`](https://github.com/NicklasKleemann/howdy-as-passkey)
at pinned commit `5eecb19bde6641b70d6c14f65cbc8f4d073e2d45`.
That external transport is Go code; it is not vendored into this repository.
See `ROADMAP.md` for the native Rust replacement plan.

IRAuth does **not** use the upstream project's Howdy PAM gate directly. The
IRAuth user service starts the bridge with `--pam-service irauth-passkey`; that
PAM service contains `pam_irauth.so`, so every ceremony flows through IRAuth's
daemon, peer-credential policy, strict camera binding check, and fresh face
verification.

## Existing installation: adopt it

If `~/.local/bin/howdy-bridge` and the TPM-sealed
`~/.config/howdy-passkey-bridge/vault.key.tpm` already exist:

```bash
irauthctl passkey adopt
```

This creates/enables `irauth-passkey.service`, disables the old competing user
service, and leaves the binary, vault, sealed key and existing WebAuthn
credentials untouched. No Go compiler is used by the adopt path.

## Clean installation

```bash
irauthctl passkey install
```

This checks out the exact pinned upstream commit and builds that optional
transport. A Go compiler is therefore needed for this one command in v0.1.
IRAuth itself and its system authentication stack remain Rust.

Strict passkey setup requires `/dev/tpmrm0` and read/write access in the current
login session. IRAuth does not expose the upstream software-only passphrase mode
through its strict passkey commands.

After installation/adoption, browsers see the authenticator over USB/IP. Choose
**Use your security key** in Chromium/Chrome/Brave.
