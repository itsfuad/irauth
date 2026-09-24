# Architecture

IRAuth separates **hardware policy**, **biometric recognition**, and **system
authentication**.

```text
PAM consumer (sudo / GDM / polkit / pamtester)
        |
        | pam_irauth.so, V1 local protocol
        v
 /run/irauth/irauthd.sock
        |
        v
     irauthd  -- SO_PEERCRED + serialization + rate limit
        |
        +--> re-read Howdy device_path
        |        |
        |        +--> strict IR/depth hardware policy (fail closed)
        |
        v
  Howdy backend (v0.1) --> accepted Linux IR/depth camera

Browser -> CTAP2 virtual authenticator -> pamtester irauth-passkey
                                      -> pam_irauth.so -> irauthd -> Howdy
                                      -> TPM 2.0 credential signing
```

The daemon accepts non-root authentication requests only when the Unix peer UID
matches the requested account. Root PAM consumers may authenticate the target
account selected by PAM. Face checks are serialized because most integrated IR
cameras cannot safely serve concurrent recognition processes.

The hardware layer refuses ordinary RGB cameras by default. A device is strict
only when its Linux video-node name explicitly identifies IR/depth hardware or
its exact USB VID:PID/interface selector is present in
`/etc/irauth/hardware.ids` after manual hardware verification.

Crucially, hardware validation is not only an installation check. Before every
face ceremony, `irauthd` reads Howdy's `[video] device_path`, resolves symlinks
such as `/dev/v4l/by-path/...`, and confirms that exact node still satisfies the
strict hardware policy. Changing Howdy later to a normal RGB webcam therefore
causes IRAuth authentication to fail closed.

## PAM migration

IRAuth captures the existing Howdy PAM module line for its private
`irauth-howdy` backend service, then validates face recognition through that
isolated service before touching system PAM. Setup migrates selected active
Howdy lines in `sudo` and `polkit-1`; it includes `gdm-password` only with
`--with-login`. Each direct Howdy auth line is commented and replaced by one
`sufficient pam_irauth.so` check at that position, so a face failure continues
to the existing password stack. Changes are snapshotted as a transaction and
restored on failure.

`howdy-only` is a legacy Howdy-as-passkey compatibility service. IRAuth-managed
passkeys use `/etc/pam.d/irauth-passkey`, so new setup leaves `howdy-only`
untouched. Existing migrated versions remain in the migration manifest and
retain their `.irauth.bak` restoration path; uninstall restores those files.

GDM has distro-specific PAM ordering. On the reviewed Fedora stack in this
environment, `pam_selinux_permit.so` precedes a direct `pam_howdy.so` sufficient
line, followed by `substack password-auth`. Therefore the planned opt-in is to
replace that direct Howdy line in place with `pam_irauth.so sufficient`, leaving
`password-auth` intact. The installer does not edit GDM by default; operators
must re-inspect the target machine's stack and keep a tested root recovery path.
