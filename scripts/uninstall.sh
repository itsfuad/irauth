#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run with sudo" >&2; exit 1; fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IRAUTHCTL="$(command -v irauthctl || true)"
if [[ -z "$IRAUTHCTL" && -x /usr/local/bin/irauthctl ]]; then
  IRAUTHCTL=/usr/local/bin/irauthctl
fi

# Stop the per-user bridge before removing its PAM service/module. Never touch
# the user's vault or TPM key; if the user manager is unavailable, report it.
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
  user_id="$(id -u "$SUDO_USER")"
  user_runtime="/run/user/$user_id"
  if [[ -S "$user_runtime/bus" ]] && command -v runuser >/dev/null 2>&1; then
    service_stopped=0
    if runuser -u "$SUDO_USER" -- env \
      XDG_RUNTIME_DIR="$user_runtime" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
      systemctl --user disable --now irauth-passkey.service; then
      service_stopped=1
    else
      echo "Warning: could not stop irauth-passkey.service for $SUDO_USER; stop it manually." >&2
    fi
    user_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    managed_unit="$user_home/.config/systemd/user/irauth-passkey.service"
    if [[ $service_stopped -eq 1 && -f "$managed_unit.irauth-created" ]]; then
      rm -f -- "$managed_unit" "$managed_unit.irauth-created"
      runuser -u "$SUDO_USER" -- env \
        XDG_RUNTIME_DIR="$user_runtime" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
        systemctl --user daemon-reload || true
    fi
  else
    echo "Warning: user manager unavailable; stop irauth-passkey.service manually before logout." >&2
  fi
else
  echo "Warning: no SUDO_USER was provided; stop the desktop user's irauth-passkey.service manually." >&2
fi

for backup in /etc/pam.d/*.irauth.bak; do
  [[ -f "$backup" && ! -L "$backup" ]] || continue
  service="${backup##*/}"
  service="${service%.irauth.bak}"
  if [[ ! -L "/etc/pam.d/$service" ]]; then
    if [[ -x "$IRAUTHCTL" && -f "/etc/pam.d/$service" ]]; then
      "$IRAUTHCTL" pam disable "$service"
    else
      cp -a --remove-destination -- "$backup" "/etc/pam.d/$service"
      echo "Restored PAM service: $service"
    fi
  fi
done
if [[ -f /etc/irauth/pam-migrated.list ]]; then
  while IFS= read -r service_path; do
    [[ -n "$service_path" ]] || continue
    backup="$service_path.irauth.bak"
    if [[ -f "$backup" && ! -L "$backup" && ! -L "$service_path" ]]; then
      cp -a --remove-destination -- "$backup" "$service_path"
      echo "Restored migrated PAM service: $service_path"
    fi
  done < /etc/irauth/pam-migrated.list
fi
systemctl disable --now irauthd.service 2>/dev/null || true
for config in \
  /usr/local/etc/howdy/config.ini \
  /etc/howdy/config.ini \
  /lib/security/howdy/config.ini \
  /usr/lib/security/howdy/config.ini \
  /usr/lib64/howdy/config.ini \
  /usr/local/lib64/howdy/config.ini; do
  if [[ -f "$config.irauth.bak" && ! -L "$config.irauth.bak" ]]; then
    cp -a --remove-destination -- "$config.irauth.bak" "$config"
    echo "Restored Howdy camera configuration: $config"
  fi
done
rm -f /usr/local/bin/irauthd /usr/local/bin/irauthctl
rm -f /usr/lib64/security/pam_irauth.so /usr/lib/x86_64-linux-gnu/security/pam_irauth.so
if [[ -f /etc/irauth/.created-daemon-unit ]] && cmp -s "$ROOT/systemd/irauthd.service" /usr/lib/systemd/system/irauthd.service; then
  rm -f /usr/lib/systemd/system/irauthd.service
fi
if [[ -f /etc/irauth/.created-vhci-rule ]] && cmp -s "$ROOT/udev/70-irauth-vhci.rules" /etc/udev/rules.d/70-irauth-vhci.rules; then
  rm -f /etc/udev/rules.d/70-irauth-vhci.rules
fi
if [[ -f /etc/irauth/.created-modules-load ]] && printf 'vhci-hcd\n' | cmp -s - /etc/modules-load.d/irauth-vhci.conf; then
  rm -f /etc/modules-load.d/irauth-vhci.conf
fi
if [[ -f /etc/irauth/.created-howdy-pam ]]; then
  rm -f /etc/pam.d/irauth-howdy
fi
if [[ -f /etc/irauth/.created-passkey-pam ]] && cmp -s "$ROOT/pam/irauth-passkey" /etc/pam.d/irauth-passkey; then
  rm -f /etc/pam.d/irauth-passkey
fi
rm -f /etc/irauth/.created-vhci-rule /etc/irauth/.created-daemon-unit \
  /etc/irauth/.created-modules-load /etc/irauth/.created-howdy-pam \
  /etc/irauth/.created-passkey-pam /etc/irauth/pam-migrated.list
systemctl daemon-reload
udevadm control --reload 2>/dev/null || true
echo "IRAuth binaries and PAM hooks removed. Howdy camera backup restored when present. User passkey vaults were left untouched."
