Name:           irauth
Version:        0.1.0
Release:        1%{?dist}
Summary:        Hardware-gated IR face authentication stack for Linux
License:        MIT
URL:            https://github.com/itsfuad/irauth
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  pam-devel
Requires:       pam
Requires:       pamtester
Requires:       v4l-utils
Requires:       tpm2-tools
Requires:       usbip
Requires:       fido2-tools

%description
IRAuth provides a Rust daemon, PAM module, hardware policy, diagnostics and a
TPM-backed passkey integration for Linux systems with real IR/depth cameras.
Howdy is the v0.1 recognition backend and must be installed separately.

%prep
%autosetup

%build
cargo build --release --workspace

%install
install -Dm0755 target/release/irauthd %{buildroot}%{_bindir}/irauthd
install -Dm0755 target/release/irauthctl %{buildroot}%{_bindir}/irauthctl
install -Dm0755 target/release/libpam_irauth.so %{buildroot}%{_libdir}/security/pam_irauth.so
mkdir -p %{buildroot}%{_unitdir}
sed 's#ExecStart=/usr/local/bin/irauthd#ExecStart=%{_bindir}/irauthd#' systemd/irauthd.service > %{buildroot}%{_unitdir}/irauthd.service
chmod 0644 %{buildroot}%{_unitdir}/irauthd.service
install -Dm0644 udev/70-irauth-vhci.rules %{buildroot}%{_udevrulesdir}/70-irauth-vhci.rules
install -Dm0644 config/hardware.ids %{buildroot}%{_sysconfdir}/irauth/hardware.ids
install -Dm0644 pam/irauth-passkey %{buildroot}%{_sysconfdir}/pam.d/irauth-passkey

%files
%license LICENSE
%doc README.md SECURITY.md docs/
%{_bindir}/irauthd
%{_bindir}/irauthctl
%{_libdir}/security/pam_irauth.so
%{_unitdir}/irauthd.service
%{_udevrulesdir}/70-irauth-vhci.rules
%config(noreplace) %{_sysconfdir}/irauth/hardware.ids
%config(noreplace) %{_sysconfdir}/pam.d/irauth-passkey

%post
%systemd_post irauthd.service

%preun
%systemd_preun irauthd.service

%postun
%systemd_postun_with_restart irauthd.service

%changelog
* Thu Sep 24 2026 itsfuad <fuad.cs22@gmail.com> - 0.1.0-1
- Initial Rust architecture
