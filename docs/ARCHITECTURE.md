# Architecture

IRAuth separates **biometric recognition** from **system authentication**.

```text
PAM consumer (sudo / GDM / polkit / pamtester)
        |
        | pam_irauth.so, V1 local protocol
        v
 /run/irauth/irauthd.sock
        |
        v
     irauthd  -- peer UID policy + serialization + rate limit
        |
        v
  Howdy backend (v0.1)
        |
        +--> Linux-visible IR/depth camera

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
