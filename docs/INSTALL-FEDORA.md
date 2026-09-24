# Fedora installation

IRAuth targets Fedora first and is designed to work with SELinux enforcing.

## Prerequisite: Howdy

v0.1 deliberately does not silently enable a third-party COPR. Install a
working Howdy package/source build using the method you trust. You do not need
to manually edit Howdy's camera path: IRAuth setup validates Linux-visible IR
hardware and binds Howdy to the accepted device.

Then run:

```bash
sudo ./scripts/install.sh --configure
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
- back up and route direct Howdy hooks only in explicitly selected services
  (`sudo`, `polkit-1`, and optionally `gdm-password`) through `pam_irauth.so`;
  `howdy-only` is left untouched as a legacy compatibility service;
- enroll a face when Howdy has no model for the target account;
- create `irauth`, `usbip` memberships and add the user to `tss` when present;
- install the USB/IP udev rule and persistent `vhci-hcd` module load;
- verify the IR face path before enabling system authentication;
- enable `pam_irauth.so` for `sudo` and `polkit-1`; GDM/login is untouched unless
  `--with-login` is explicitly requested. Inspect `/etc/pam.d/gdm-password` and
  preserve root/sudo recovery before opting in.

A complete logout/login is required once after group changes.

### If howdy-as-passkey is already working

Use the existing TPM vault and GitHub credentials without rebuilding the
transport. Adoption checks existing vault/key files and rewires only the user
service; it does not initialize a TPM key or register a credential:

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

## Packaging and removal

The Fedora RPM builds the Rust workspace on the package build host and installs
distro paths; the runtime machine does not compile IRAuth when installing the
RPM. The convenience `scripts/install.sh` is a source installer and does build
on the target. Debian/Ubuntu package metadata is not yet maintained; those
systems currently use the source installer. Howdy remains a separately trusted
prerequisite. `scripts/uninstall.sh` restores IRAuth-managed PAM/Howdy backups
and removes system integration files but deliberately leaves per-user passkey
vaults and TPM material untouched.
