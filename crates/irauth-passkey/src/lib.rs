use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const UPSTREAM_URL: &str = "https://github.com/NicklasKleemann/howdy-as-passkey.git";
pub const PINNED_COMMIT: &str = "5eecb19bde6641b70d6c14f65cbc8f4d073e2d45";
pub const SERVICE_NAME: &str = "irauth-passkey.service";

#[derive(Debug, Clone)]
pub struct Diagnosis {
    pub ready: bool,
    pub detail: String,
}

pub fn cli(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("adopt") => adopt(),
        Some("install") => install(),
        Some("start") => systemctl(&["start", SERVICE_NAME]),
        Some("stop") => systemctl(&["stop", SERVICE_NAME]),
        Some("status") => {
            let d = diagnose();
            println!(
                "{}: {}",
                if d.ready { "ready" } else { "not ready" },
                d.detail
            );
            Ok(())
        }
        Some("test") => test(),
        _ => Err("usage: irauthctl passkey adopt|install|start|stop|status|test".into()),
    }
}

pub fn diagnose() -> Diagnosis {
    let Ok(home) = home_dir() else {
        return Diagnosis {
            ready: false,
            detail: "HOME unavailable".into(),
        };
    };
    let binary = home.join(".local/bin/howdy-bridge");
    let config = home.join(".config/howdy-passkey-bridge");
    let vault = config.join("vault.json");
    let sealed = config.join("vault.key.tpm");
    let unit = home.join(".config/systemd/user").join(SERVICE_NAME);
    let active = Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", SERVICE_NAME])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let virtual_fido = virtual_fido_attached();
    let mut missing = Vec::new();
    if !user_owned_file(&binary, false) {
        missing.push("user-owned bridge binary");
    }
    if !user_owned_file(&vault, true) || fs::metadata(&vault).map(|m| m.len() == 0).unwrap_or(true)
    {
        missing.push("private, non-empty vault.json");
    }
    if !user_owned_file(&sealed, true) {
        missing.push("private TPM-sealed vault key");
    }
    if !unit.is_file() {
        missing.push("user service");
    }
    if !active {
        missing.push("running service");
    }
    if !virtual_fido {
        missing.push("virtual FIDO device attachment");
    }
    Diagnosis {
        ready: missing.is_empty(),
        detail: if missing.is_empty() {
            "TPM-backed bridge active; virtual FIDO device attached".into()
        } else {
            format!("missing: {}", missing.join(", "))
        },
    }
}

fn user_owned_file(path: &Path, private: bool) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| {
            let mode = metadata.permissions().mode();
            metadata.file_type().is_file()
                && metadata.uid() == unsafe { geteuid() }
                && if private {
                    mode & 0o077 == 0 && mode & 0o400 != 0
                } else {
                    mode & 0o022 == 0 && mode & 0o100 != 0
                }
        })
        .unwrap_or(false)
}

fn virtual_fido_attached() -> bool {
    Command::new("fido2-token")
        .arg("-L")
        .output()
        .map(|output| {
            output.status.success()
                && reports_virtual_fido(&String::from_utf8_lossy(&output.stdout))
        })
        .unwrap_or(false)
}

fn install() -> Result<(), Box<dyn std::error::Error>> {
    require_desktop_user()?;
    require_command("git")?;
    require_command("go").map_err(|_| "the optional v0.1 CTAP2 transport is built from a pinned upstream Go project; install Go or use `irauthctl passkey adopt` with an existing howdy-bridge binary")?;
    require_command("systemctl")?;
    require_command("usbip")?;
    require_tpm_access()?;

    let home = home_dir()?;
    let source = home.join(".local/share/irauth/howdy-as-passkey");
    let bin_dir = home.join(".local/bin");
    let config = home.join(".config/howdy-passkey-bridge");
    fs::create_dir_all(source.parent().unwrap_or(&home))?;
    fs::create_dir_all(&bin_dir)?;
    fs::create_dir_all(&config)?;

    checkout_upstream(&source)?;
    let binary = bin_dir.join("howdy-bridge");
    println!("==> building pinned FIDO2 bridge {PINNED_COMMIT}");
    run_ok(
        Command::new("go")
            .arg("build")
            .arg("-trimpath")
            .arg("-o")
            .arg(&binary)
            .arg("./cmd/howdy-bridge")
            .current_dir(source.join("src/virtual-fido")),
        "build howdy bridge",
    )?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;

    let sealed = config.join("vault.key.tpm");
    if !sealed.is_file() {
        let vault = config.join("vault.json");
        if vault.is_file() && fs::metadata(&vault)?.len() > 0 {
            let pass = prompt_secret("Existing howdy-passkey vault passphrase: ")?;
            let mut cmd = Command::new(&binary);
            cmd.arg("--tpm-init").env("HOWDY_BRIDGE_PASSPHRASE", &pass);
            run_ok(&mut cmd, "migrate passkey vault to TPM")?;
        } else {
            run_ok(
                Command::new(&binary).arg("--tpm-init"),
                "initialize TPM-sealed passkey vault",
            )?;
        }
    }

    configure_service(&binary, &config)?;
    println!("IRAuth passkey bridge installed and TPM-bound.");
    Ok(())
}

/// Adopt an existing manual howdy-as-passkey installation without building any
/// Go code. This is the preferred migration path for users who already have a
/// working TPM-backed bridge and preserves their existing WebAuthn credentials.
fn adopt() -> Result<(), Box<dyn std::error::Error>> {
    require_desktop_user()?;
    require_command("systemctl")?;
    require_command("usbip")?;
    require_tpm_access()?;
    let home = home_dir()?;
    let binary = home.join(".local/bin/howdy-bridge");
    let config = home.join(".config/howdy-passkey-bridge");
    if !user_owned_file(&binary, false) {
        return Err(format!("existing bridge binary not found or unsafe at {}; use `irauthctl passkey install` only if setting up a new bridge", binary.display()).into());
    }
    let vault = config.join("vault.json");
    if !user_owned_file(&vault, true) || fs::metadata(&vault)?.len() == 0 {
        return Err(format!("existing passkey vault missing, empty, or not privately owned at {}; IRAuth will not initialize or replace it", vault.display()).into());
    }
    let sealed = config.join("vault.key.tpm");
    if !user_owned_file(&sealed, true) {
        return Err(format!(
            "TPM-sealed passkey key not found at {}; IRAuth will not adopt a software-only vault",
            sealed.display()
        )
        .into());
    }
    configure_service(&binary, &config)?;
    let diagnosis = diagnose();
    if !diagnosis.ready {
        return Err(format!(
            "passkey service wiring completed, but verification failed: {}",
            diagnosis.detail
        )
        .into());
    }
    println!("Adopted the existing TPM-backed passkey bridge; vault.json, vault.key.tpm and registered credentials were not modified.");
    println!(
        "Run `irauthctl passkey test` to verify face PAM and virtual FIDO device enumeration."
    );
    Ok(())
}

fn configure_service(binary: &Path, config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let home = home_dir()?;
    let unit_dir = home.join(".config/systemd/user");
    fs::create_dir_all(&unit_dir)?;
    let unit = unit_dir.join(SERVICE_NAME);
    let body = format!(
        r#"[Unit]
Description=IRAuth TPM-backed virtual FIDO2 authenticator
After=graphical-session.target

[Service]
Type=simple
ExecStart={} --pam-service irauth-passkey --vault {}/vault.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=default.target
"#,
        binary.display(),
        config.display()
    );
    if unit.exists() {
        if !fs::symlink_metadata(&unit)?.file_type().is_file() {
            return Err(
                format!("refusing non-regular user service unit {}", unit.display()).into(),
            );
        }
        if fs::read_to_string(&unit)? != body {
            return Err(format!(
                "refusing to overwrite existing user service unit {}; inspect it before adopting",
                unit.display()
            )
            .into());
        }
    } else {
        atomic_write(&unit, body.as_bytes(), 0o644)?;
        atomic_write(
            &unit.with_extension("service.irauth-created"),
            b"created\n",
            0o600,
        )?;
    }

    // Avoid two USB/IP authenticators fighting for the same endpoint when a
    // previous manual howdy-as-passkey installation exists.
    stop_legacy_service()?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", SERVICE_NAME])?;
    Ok(())
}

fn stop_legacy_service() -> Result<(), Box<dyn std::error::Error>> {
    let service = "howdy-passkey-bridge.service";
    let active = Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", service])
        .status()?
        .success();
    let enabled = Command::new("systemctl")
        .args(["--user", "is-enabled", "--quiet", service])
        .status()?
        .success();
    if active {
        systemctl(&["stop", service])?;
    }
    if enabled {
        systemctl(&["disable", service])?;
    }
    Ok(())
}

fn require_desktop_user() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { geteuid() } == 0 {
        Err("passkey commands must run as the desktop user, not through sudo".into())
    } else {
        Ok(())
    }
}

fn require_tpm_access() -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new("/dev/tpmrm0").exists() {
        return Err("strict passkey mode requires TPM 2.0 at /dev/tpmrm0".into());
    }
    fs::OpenOptions::new().read(true).write(true).open("/dev/tpmrm0")
        .map_err(|e| format!("TPM is not accessible in this login session ({e}); log out/in after setup so the tss group becomes active"))?;
    Ok(())
}

fn checkout_upstream(source: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !source.join(".git").is_dir() {
        if source.exists() {
            fs::remove_dir_all(source)?;
        }
        run_ok(
            Command::new("git")
                .args(["clone", "--no-checkout", UPSTREAM_URL])
                .arg(source),
            "clone passkey bridge",
        )?;
    }
    run_ok(
        Command::new("git")
            .args(["fetch", "--depth", "1", "origin", PINNED_COMMIT])
            .current_dir(source),
        "fetch pinned passkey bridge",
    )?;
    run_ok(
        Command::new("git")
            .args(["checkout", "--detach", PINNED_COMMIT])
            .current_dir(source),
        "checkout pinned passkey bridge",
    )?;
    Ok(())
}

fn reports_virtual_fido(output: &str) -> bool {
    output.to_ascii_lowercase().contains("virtual fido")
}

fn test() -> Result<(), Box<dyn std::error::Error>> {
    let user = env::var("USER").map_err(|_| "USER is not set")?;
    println!("==> face verification through pam_irauth (look at the IR camera)");
    run_ok(
        Command::new("pamtester").args(["irauth-passkey", &user, "authenticate"]),
        "passkey PAM verification",
    )?;
    if command_exists("fido2-token") {
        let output = Command::new("fido2-token").arg("-L").output()?;
        let text = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() || !reports_virtual_fido(&text) {
            return Err(format!(
                "fido2-token did not identify the virtual FIDO authenticator (exit {}; output: {}). Check `usbip port`, the user service, and usbip group/session access",
                output.status,
                text.trim()
            )
            .into());
        }
        print!("{text}");
    } else {
        println!("fido2-token is not installed; PAM/TPM checks passed, skipping CTAP enumeration");
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl --user {} failed", args.join(" ")).into())
    }
}

fn prompt_secret(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let _ = Command::new("stty").arg("-echo").status();
    let mut input = String::new();
    let result = io::stdin().read_line(&mut input);
    let _ = Command::new("stty").arg("echo").status();
    println!();
    result?;
    let secret = input.trim_end_matches(['\r', '\n']).to_owned();
    if secret.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty passphrase",
        ));
    }
    Ok(secret)
}

fn home_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".into())
}

fn require_command(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if command_exists(name) {
        Ok(())
    } else {
        Err(format!("required command not found: {name}").into())
    }
}

fn command_exists(name: &str) -> bool {
    env::var_os("PATH")
        .map(|path| env::split_paths(&path).any(|p| p.join(name).is_file()))
        .unwrap_or(false)
}

fn run_ok(cmd: &mut Command, what: &str) -> Result<(), Box<dyn std::error::Error>> {
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what} failed with {status}").into())
    }
}

fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(tmp, path)
}

extern "C" {
    fn geteuid() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn adoption_files_must_be_regular_user_owned_and_private() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("irauth-passkey-test-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let vault = root.join("vault.json");
        fs::write(&vault, b"existing vault").unwrap();
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(user_owned_file(&vault, true));
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!user_owned_file(&vault, true));
        let link = root.join("vault-link.json");
        symlink(&vault, &link).unwrap();
        assert!(!user_owned_file(&link, true));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fido_listing_identifies_virtual_authenticator_without_relying_on_vendor_name() {
        let listing = "/dev/hidraw3: vendor=0x0000, product=0x0000 (No Company Virtual FIDO)";
        assert!(super::reports_virtual_fido(listing));
        assert!(!super::reports_virtual_fido(
            "/dev/hidraw3: vendor=0x0000, product=0x0000"
        ));
    }
}
