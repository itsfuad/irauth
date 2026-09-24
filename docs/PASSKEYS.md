# Passkeys

IRAuth v0.1 deliberately reuses the CTAP2 implementation from
[`NicklasKleemann/howdy-as-passkey`](https://github.com/NicklasKleemann/howdy-as-passkey)
at pinned commit `5eecb19bde6641b70d6c14f65cbc8f4d073e2d45`.

IRAuth does **not** use that project's Howdy PAM gate directly. The installed
user service starts the bridge with `--pam-service irauth-passkey`; that PAM
service contains `pam_irauth.so`, so the ceremony flows through IRAuth's daemon,
peer-credential policy and fresh face verification.

Strict passkey setup requires `/dev/tpmrm0`. The upstream bridge seals its vault
key to that TPM and generates/signs per-credential P-256 keys in the TPM. IRAuth
does not offer the software-only passphrase mode from this command because the
project's default security target is Windows-Hello-like hardware binding.

After `irauthctl passkey install`, browsers see the authenticator over USB/IP.
Choose **Use your security key** in Chromium/Chrome/Brave.
