# Fedora installation

IRAuth targets Fedora first and is designed to work with SELinux enforcing.

## Prerequisite: Howdy

v0.1 deliberately does not silently enable a third-party COPR. Install a
working Howdy package/source build using the method you trust, configure its
actual IR camera, and confirm normal Howdy recognition once.

Then the IRAuth path is:

```bash
sudo ./scripts/install.sh --configure
```

Setup will:

- refuse to proceed without strict IR/depth hardware evidence;
- require TPM 2.0 unless `--allow-no-tpm` is explicitly used;
- install/repair the three required Howdy dlib model files when Howdy's
  `dlib-data/install.sh` is present;
- create a face-only `irauth-howdy` PAM service from the already-working Howdy
  PAM line;
- create `irauth`, `usbip` memberships and add the user to `tss` when present;
- install the USB/IP udev rule and persistent `vhci-hcd` module load;
- verify the IR face path before enabling system authentication;
- enable `pam_irauth.so` for `sudo` and `polkit-1` (and `gdm-password` only when
  `--with-login` is requested).

A complete logout/login is required once after group changes. Then:

```bash
irauthctl passkey install
irauthctl passkey test
irauthctl doctor
```

The passkey installer transitions an existing manual `howdy-passkey-bridge`
service out of the way and installs `irauth-passkey.service`, which gates the
same TPM/FIDO2 implementation through `pam_irauth.so` and `irauthd`.
