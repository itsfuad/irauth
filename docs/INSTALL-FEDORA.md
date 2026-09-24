# Fedora installation

IRAuth targets Fedora first and is designed to work with SELinux enforcing.

## Prerequisite: Howdy

v0.1 deliberately does not silently enable a third-party COPR. Install a
working Howdy package/source build using the method you trust. You do not need
to manually edit Howdy's camera path: IRAuth setup validates Linux-visible IR
hardware and binds Howdy to the accepted device.

Then run:

```bash
sudo ./scripts/install.sh --configure --with-login
```

Setup will:

- refuse to proceed without strict IR/depth hardware evidence;
- select the already-configured strict Howdy camera, automatically bind the
  only strict node, or require `--camera /dev/videoN` when the choice is
  ambiguous;
- require TPM 2.0 unless `--allow-no-tpm` is explicitly used;
- install/repair the three required Howdy dlib model files when Howdy's
  `dlib-data/install.sh` is present;
- create a face-only `irauth-howdy` PAM service from the already-working Howdy
  PAM line;
- back up active direct Howdy PAM entries and route them through `pam_irauth.so`
  so an old Howdy hook cannot bypass the strict camera policy;
- enroll a face when Howdy has no model for the target account;
- create `irauth`, `usbip` memberships and add the user to `tss` when present;
- install the USB/IP udev rule and persistent `vhci-hcd` module load;
- verify the IR face path before enabling system authentication;
- enable `pam_irauth.so` for `sudo` and `polkit-1` (and `gdm-password` only when
  `--with-login` is requested).

A complete logout/login is required once after group changes.

### If howdy-as-passkey is already working

Use the existing TPM vault and GitHub credentials without rebuilding the
transport:

```bash
irauthctl passkey adopt
irauthctl passkey test
irauthctl doctor
```

### On a clean machine

```bash
irauthctl passkey install
irauthctl passkey test
irauthctl doctor
```

The fresh v0.1 passkey command builds a pinned external CTAP2 bridge and thus
needs Go for that optional transport only. IRAuth itself is Rust and the base
Fedora installer does not install Go.
