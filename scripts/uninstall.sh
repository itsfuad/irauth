#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run with sudo" >&2; exit 1; fi
for service in sudo polkit-1 gdm-password; do
  if [[ -e "/etc/pam.d/$service.irauth.bak" ]]; then
    /usr/local/bin/irauthctl pam disable "$service" || true
  fi
done
if [[ -f /etc/irauth/pam-migrated.list ]]; then
  while IFS= read -r service_path; do
    [[ -n "$service_path" ]] || continue
    backup="$service_path.irauth.bak"
    if [[ -f "$backup" ]]; then
      cp -a "$backup" "$service_path"
      echo "Restored PAM service: $service_path"
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
  if [[ -f "$config.irauth.bak" ]]; then
    cp -a "$config.irauth.bak" "$config"
    echo "Restored Howdy camera configuration: $config"
  fi
done
rm -f /usr/local/bin/irauthd /usr/local/bin/irauthctl
rm -f /usr/lib64/security/pam_irauth.so /usr/lib/x86_64-linux-gnu/security/pam_irauth.so
rm -f /usr/lib/systemd/system/irauthd.service
rm -f /etc/udev/rules.d/70-irauth-vhci.rules /etc/modules-load.d/irauth-vhci.conf
rm -f /etc/pam.d/irauth-howdy /etc/pam.d/irauth-passkey /etc/irauth/pam-migrated.list
systemctl daemon-reload
udevadm control --reload 2>/dev/null || true
echo "IRAuth binaries and PAM hooks removed. Howdy camera backup restored when present. User passkey vaults were left untouched."
