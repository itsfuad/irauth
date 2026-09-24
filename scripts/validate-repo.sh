#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
test -f Cargo.toml
test ! -f go.mod
if find . -path ./.git -prune -o -name '*.go' -print | grep -q .; then
  echo "unexpected Go source in Rust repository" >&2
  exit 1
fi
for crate in irauth-core irauth-hardware irauth-backend-howdy irauth-daemon irauthctl pam-irauth irauth-passkey; do
  test -f "crates/$crate/Cargo.toml"
done
grep -q 'strict_devices' crates/irauthctl/src/main.rs
grep -q 'configured_camera' crates/irauth-daemon/src/main.rs
grep -q 'strict_device_for_path' crates/irauth-daemon/src/main.rs
grep -q 'Some("adopt")' crates/irauth-passkey/src/lib.rs
grep -Fq 'crate-type = ["cdylib"]' crates/pam-irauth/Cargo.toml
grep -q 'PINNED_COMMIT' crates/irauth-passkey/src/lib.rs
grep -q 'TPM 2.0 is required' crates/irauthctl/src/main.rs
echo "repository structure checks passed"
