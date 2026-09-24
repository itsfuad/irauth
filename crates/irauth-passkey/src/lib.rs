use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
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
        Some("install") => install(),
        Some("start") => systemctl(&["start", SERVICE_NAME]),
        Some("stop") => systemctl(&["stop", SERVICE_NAME]),
        Some("status") => {
            let d = diagnose();
            println!("{}: {}", if d.ready { "ready" } else { "not ready" }, d.detail);
            Ok(())
        }
        Some("test") => test(),
        _ => Err("usage: irauthctl passkey install|start|stop|status|test".into()),
    }
}

pub fn diagnose() -> Diagnosis {
    let Ok(home) = home_dir() else { return Diagnosis { ready: false, detail: "HOME unavailable".into() } };
    let binary = home.join(".local/bin/howdy-bridge");
    let sealed = home.join(".config/howdy-passkey-bridge/vault.key.tpm");
    let unit = home.join(".config/systemd/user").join(SERVICE_NAME);
    let active = Command::new("systemctl").args(["--user", "is-active", "--quiet", SERVICE_NAME]).status().map(|s| s.success()).unwrap_or(false);
    let mut missing = Vec::new();
    if !binary.is_file() { missing.push("bridge binary"); }
    if !sealed.is_file() { missing.push("TPM-sealed vault key"); }
    if !unit.is_file() { missing.push("user service"); }
    if !active { missing.push("running service"); }
    Diagnosis {
        ready: missing.is_empty(),
        detail: if missing.is_empty() { "TPM-backed bridge active".into() } else { format!("missing: {}", missing.join(", ")) },
    }
}

fn install() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { geteuid() } == 0 {
        return Err("passkey install must run as the desktop user, not through sudo".into());
    }
    require_command("git")?;
    require_command("go")?;
    require_command("systemctl")?;
    require_command("usbip")?;
    if !Path::new("/dev/tpmrm0").exists() {
        return Err("strict passkey mode requires TPM 2.0 at /dev/tpmrm0".into());
    }
    fs::OpenOptions::new().read(true).write(true).open("/dev/tpmrm0")
        .map_err(|e| format!("TPM is not accessible in this login session ({e}); log out/in after setup so the tss group becomes active"))?;

    let home = home_dir()?;
    let source = home.join(".local/share/irauth/howdy-as-passkey");
    let bin_dir = home.join(".local/bin");
    let config = home.join(".config/howdy-passkey-bridge");
    let unit_dir = home.join(".config/systemd/user");
    fs::create_dir_all(source.parent().unwrap_or(&home))?;
    fs::create_dir_all(&bin_dir)?;
    fs::create_dir_all(&config)?;
    fs::create_dir_all(&unit_dir)?;

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
            run_ok(Command::new(&binary).arg("--tpm-init"), "initialize TPM-sealed passkey vault")?;
        }
    }

    let unit = unit_dir.join(SERVICE_NAME);
    let body = format!(r#"[Unit]
Description=IRAuth TPM-backed virtual FIDO2 authenticator
After=graphical-session.target irauthd.service

[Service]
Type=simple
ExecStart={} --pam-service irauth-passkey --vault {}/vault.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=default.target
"#, binary.display(), config.display());
    atomic_write(&unit, body.as_bytes(), 0o644)?;

    // Avoid two USB/IP authenticators fighting for the same endpoint when a
    // previous manual howdy-as-passkey installation exists.
    let _ = Command::new("systemctl").args(["--user", "disable", "--now", "howdy-passkey-bridge.service"]).status();
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", SERVICE_NAME])?;
    println!("IRAuth passkey bridge installed and TPM-bound.");
    Ok(())
}

fn checkout_upstream(source: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !source.join(".git").is_dir() {
        if source.exists() { fs::remove_dir_all(source)?; }
        run_ok(Command::new("git").args(["clone", "--no-checkout", UPSTREAM_URL]).arg(source), "clone passkey bridge")?;
    }
    run_ok(Command::new("git").args(["fetch", "--depth", "1", "origin", PINNED_COMMIT]).current_dir(source), "fetch pinned passkey bridge")?;
    run_ok(Command::new("git").args(["checkout", "--detach", PINNED_COMMIT]).current_dir(source), "checkout pinned passkey bridge")?;
    Ok(())
}

fn test() -> Result<(), Box<dyn std::error::Error>> {
    let user = env::var("USER").map_err(|_| "USER is not set")?;
    println!("==> face verification through pam_irauth (look at the IR camera)");
    run_ok(Command::new("pamtester").args(["irauth-passkey", &user, "authenticate"]), "passkey PAM verification")?;
    if command_exists("fido2-token") {
        let output = Command::new("fido2-token").arg("-L").output()?;
        let text = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() || !text.to_ascii_lowercase().contains("virtual fido") {
            return Err("fido2-token did not see the virtual FIDO authenticator".into());
        }
        print!("{text}");
    } else {
        println!("fido2-token is not installed; PAM/TPM checks passed, skipping CTAP enumeration");
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("systemctl").arg("--user").args(args).status()?;
    if status.success() { Ok(()) } else { Err(format!("systemctl --user {} failed", args.join(" ")).into()) }
}

fn prompt_secret(prompt: &str) -> io::Result<String> {
    print!("{prompt}"); io::stdout().flush()?;
    let _ = Command::new("stty").arg("-echo").status();
    let mut input = String::new();
    let result = io::stdin().read_line(&mut input);
    let _ = Command::new("stty").arg("echo").status();
    println!();
    result?;
    let secret = input.trim_end_matches(['\r', '\n']).to_owned();
    if secret.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty passphrase")); }
    Ok(secret)
}

fn home_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    env::var_os("HOME").map(PathBuf::from).ok_or_else(|| "HOME is not set".into())
}

fn require_command(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if command_exists(name) { Ok(()) } else { Err(format!("required command not found: {name}").into()) }
}

fn command_exists(name: &str) -> bool {
    env::var_os("PATH").into_iter().flat_map(env::split_paths).any(|p| p.join(name).is_file())
}

fn run_ok(cmd: &mut Command, what: &str) -> Result<(), Box<dyn std::error::Error>> {
    let status = cmd.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).status()?;
    if status.success() { Ok(()) } else { Err(format!("{what} failed with {status}").into()) }
}

fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(tmp, path)
}

extern "C" { fn geteuid() -> u32; }
