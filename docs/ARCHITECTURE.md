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
its USB VID:PID is present in `/etc/irauth/hardware.ids` after manual hardware
verification.

Crucially, hardware validation is not only an installation check. Before every
face ceremony, `irauthd` reads Howdy's `[video] device_path`, resolves symlinks
such as `/dev/v4l/by-path/...`, and confirms that exact node still satisfies the
strict hardware policy. Changing Howdy later to a normal RGB webcam therefore
causes IRAuth authentication to fail closed.
