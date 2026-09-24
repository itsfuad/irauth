# Security model

IRAuth is security-sensitive software and v0.1 has **not** received an
independent security audit. Keep a password and a second GitHub/2FA recovery
method configured.

## Security invariants

1. **No RGB downgrade.** Strict setup stops unless Linux exposes an IR/depth
   video node or its exact USB VID:PID/interface selector is explicitly verified in
   `/etc/irauth/hardware.ids`. Setup binds Howdy to that accepted node, and
   `irauthd` re-checks Howdy's exact `device_path` before every authentication.
   A later switch to an RGB webcam therefore fails closed. During setup, active
   direct Howdy PAM entries in selected services are backed up and routed through
   `pam_irauth.so`; otherwise those hooks could bypass IRAuth's hardware policy.
   New setup selects sudo/polkit and only selects GDM with explicit `--with-login`.
   The legacy `howdy-only` compatibility service is no longer automatically changed.
2. **Fresh verification.** `pam_irauth.so` does not cache success. Every PAM or
   WebAuthn ceremony asks `irauthd`, which invokes the face backend again.
3. **Fail closed.** Missing daemon, malformed IPC, Howdy failure, missing models,
   timeout/failure in PAM, or peer-policy failure returns authentication error.
4. **Peer identity.** `irauthd` reads `SO_PEERCRED`. A non-root client may only
   request face verification for its own UID; root PAM consumers may request the
   PAM-selected account.
5. **Serialized camera access.** Face checks are serialized to avoid races and
   accidental cross-talk on integrated cameras. The daemon also caps IPC lines
   at 1024 bytes and uses four workers with a bounded queue, dropping excess
   connections rather than spawning unbounded threads.
6. **Hardware-bound passkeys.** `irauthctl passkey adopt` and `passkey install`
   require TPM 2.0. The pinned v0.1 FIDO2 transport seals its vault key to the
   TPM and uses TPM-generated credential keys. IRAuth intentionally does not
   expose its software-only mode through the strict commands.

## Trust boundaries

The PAM module is intentionally small: it gets the PAM user, sends a local
request, and maps only an explicit `OK` response to `PAM_SUCCESS`. Recognition,
hardware policy and process execution stay out of the PAM consumer. PAM's
`reason=` field is diagnostic/log metadata only; it does not alter authorization.

`irauthd` runs as root because login managers and PAM consumers must be able to
authenticate users before a user session exists. Its systemd unit uses a
read-only filesystem view, namespace restrictions, `NoNewPrivileges`, and a
minimal writable runtime directory. Root compromise remains game-over: an
attacker with root can replace PAM configuration or the daemon and ask the TPM
to sign.

The v0.1 biometric backend is Howdy. Howdy itself warns that it is not a
password replacement and has not got the secure camera path/anti-spoofing
properties of commercial Windows Hello implementations. IR/depth hardware is a
required baseline, not a claim of Windows Hello certification.

## SELinux

IRAuth does not disable SELinux and the installer must not add permissive rules.
The initial Fedora release runs under the distribution's normal service/PAM
labels. If enforcing SELinux blocks a particular camera/backend path, collect
the AVC denial and add a narrowly scoped policy in a reviewed release rather
than using `setenforce 0` or broad `audit2allow` output.

## Recovery

IRAuth inserts or substitutes an `auth sufficient` check so a failed or
unavailable face check falls through to the existing password stack. Before
modifying a PAM service it creates `/etc/pam.d/<service>.irauth.bak` without
overwriting an existing backup. `irauthctl pam disable SERVICE` restores it.
Setup snapshots selected PAM files and the migration manifest and rolls them
back if any enablement step fails. Uninstall restores enabled and migrated
stacks. GDM remains opt-in; inspect its local PAM ordering and verify sudo/root
recovery before enabling login integration.

Passkey adoption only rewires the user service: it does not run `--tpm-init`,
change `vault.json` or `vault.key.tpm`, or register credentials. Uninstall keeps
both user files by default. Clearing/replacing the TPM can make TPM-bound
credentials unusable.

## Limitations and threat model

Howdy supplies the v0.1 recognition and liveness behavior. IR/depth device
selection is a strict hardware gate, not proof that the camera path is secure,
that frames cannot be spoofed, or that the biometric model is protected like a
platform credential. IRAuth is Windows-Hello-style in the user experience only;
it is not Windows Hello, does not claim hardware-level equivalence, and has not
received an independent security audit. Password authentication should remain
enabled with independent recovery factors.
