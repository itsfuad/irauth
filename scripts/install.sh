#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURE=0
WITH_LOGIN=0
ALLOW_NO_TPM=0
TARGET_USER="${SUDO_USER:-${USER:-}}"
CAMERA=""

usage() {
  cat <<USAGE
Usage: sudo ./scripts/install.sh [--configure] [--with-login] [--allow-no-tpm] [--user USER] [--camera PATH]

--configure      run hardware-gated IRAuth setup after installation
--with-login     also add pam_irauth.so to gdm-password when present
--allow-no-tpm   evaluation only; PAM auth may work but strict passkeys remain unavailable
--user USER      account to enroll/configure (defaults to SUDO_USER)
--camera PATH    explicit strict IR V4L2 node when multiple nodes are detected
USAGE
}

while (($#)); do
  case "$1" in
    --configure) CONFIGURE=1 ;;
    --with-login) WITH_LOGIN=1 ;;
    --allow-no-tpm) ALLOW_NO_TPM=1 ;;
    --user) shift; TARGET_USER="${1:-}" ;;
    --camera) shift; CAMERA="${1:-}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ $EUID -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi
if [[ -z "$TARGET_USER" || "$TARGET_USER" == root ]]; then
  echo "Cannot determine the desktop user. Pass --user USER." >&2
  exit 1
fi

source /etc/os-release
case "${ID:-}" in
  fedora)
    dnf install -y rust cargo gcc pam-devel pamtester v4l-utils tpm2-tools usbip fido2-tools
    PAM_DIR=/usr/lib64/security
    ;;
  debian|ubuntu|linuxmint)
    apt-get update
    apt-get install -y rustc cargo gcc libpam0g-dev pamtester v4l-utils tpm2-tools usbip fido2-tools
    PAM_DIR=/usr/lib/x86_64-linux-gnu/security
    ;;
  *)
    echo "Unsupported automatic package install for ${ID:-unknown}. Install Rust, PAM headers, pamtester, v4l-utils, TPM2 tools and usbip, then rerun." >&2
    exit 1
    ;;
esac

if ! command -v howdy >/dev/null 2>&1; then
  cat >&2 <<'HOWDY'
Howdy is required by IRAuth v0.1 but is intentionally not installed from a
third-party repository without your approval. Install a working Howdy package
or source build first, then rerun this command. IRAuth setup will select/bind the IR camera.
See docs/INSTALL-FEDORA.md.
HOWDY
  exit 1
fi

echo "==> building Rust workspace"
cd "$ROOT"
cargo build --release --workspace

echo "==> installing binaries and PAM module"
install -Dm0755 target/release/irauthd /usr/local/bin/irauthd
install -Dm0755 target/release/irauthctl /usr/local/bin/irauthctl
install -Dm0755 target/release/libpam_irauth.so "$PAM_DIR/pam_irauth.so"
install -d -m0755 /etc/irauth
systemd_unit=/usr/lib/systemd/system/irauthd.service
if [[ -e "$systemd_unit" || -L "$systemd_unit" ]]; then
  if cmp -s systemd/irauthd.service "$systemd_unit"; then
    echo "==> systemd unit already configured"
  else
    echo "==> preserving existing $systemd_unit"
  fi
else
  install -Dm0644 systemd/irauthd.service "$systemd_unit"
  touch /etc/irauth/.created-daemon-unit
fi
for config_pair in \
  "udev/70-irauth-vhci.rules:/etc/udev/rules.d/70-irauth-vhci.rules" \
  "config/hardware.ids:/etc/irauth/hardware.ids" \
  "pam/irauth-passkey:/etc/pam.d/irauth-passkey"; do
  source_file="${config_pair%%:*}"
  target_file="${config_pair#*:}"
  if [[ -e "$target_file" || -L "$target_file" ]]; then
    echo "==> preserving existing $target_file"
  else
    install -Dm0644 "$source_file" "$target_file"
    case "$target_file" in
      /etc/udev/rules.d/70-irauth-vhci.rules) touch /etc/irauth/.created-vhci-rule ;;
      /etc/pam.d/irauth-passkey) touch /etc/irauth/.created-passkey-pam ;;
    esac
  fi
done

systemctl daemon-reload
udevadm control --reload

if [[ $CONFIGURE -eq 1 ]]; then
  args=(setup --user "$TARGET_USER")
  [[ -n "$CAMERA" ]] && args+=(--camera "$CAMERA")
  [[ $WITH_LOGIN -eq 1 ]] && args+=(--with-login)
  [[ $ALLOW_NO_TPM -eq 1 ]] && args+=(--allow-no-tpm)
  /usr/local/bin/irauthctl "${args[@]}"
else
  echo
  echo "Installed. Configure with: sudo irauthctl setup --user $TARGET_USER"
fi
