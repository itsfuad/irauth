use irauth_backend_howdy::{bind_camera, configured_camera, repair_dlib_assets, Backend};
use irauth_core::{encode_request, Request, SOCKET_PATH};
use irauth_hardware::{is_strict_device_path, probe, strict_devices, Evidence, VERIFIED_IDS_PATH};
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

extern "C" {
    fn geteuid() -> u32;
}

fn main() {
    if let Err(err) = run() {
        eprintln!("irauthctl: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("hardware") => cmd_hardware(),
        Some("status") => cmd_status(),
        Some("doctor") => cmd_doctor(),
        Some("enroll") => cmd_enroll(args.get(1).map(String::as_str)),
        Some("test") => cmd_test(args.get(1).map(String::as_str)),
        Some("setup") => cmd_setup(&args[1..]),
        Some("pam") => cmd_pam(&args[1..]),
        Some("passkey") => irauth_passkey::cli(&args[1..]),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unknown command: {other}").into()),
    }
}

fn print_help() {
    println!(
        r#"IRAuth control utility

Usage:
  irauthctl hardware
  irauthctl status
  irauthctl doctor
  irauthctl enroll [USER]
  irauthctl test [USER]
  sudo irauthctl setup [--user USER] [--camera PATH] [--with-login] [--allow-no-tpm]
  sudo irauthctl pam enable SERVICE
  sudo irauthctl pam disable SERVICE
  irauthctl passkey adopt|install|start|stop|status|test
"#
    );
}

fn cmd_hardware() -> Result<(), Box<dyn std::error::Error>> {
    let devices = probe()?;
    if devices.is_empty() {
        println!("No V4L2 video devices found.");
        return Ok(());
    }
    for dev in devices {
        let evidence = match dev.evidence {
            Evidence::IrName => "IR name",
            Evidence::DepthName => "depth name",
            Evidence::VerifiedUsbId => "verified USB ID",
            Evidence::None => "not accepted",
        };
        let usb = match (&dev.usb_id, &dev.usb_interface) {
            (Some(id), Some(interface)) => format!("{id}@{interface}"),
            (Some(id), None) => id.clone(),
            _ => "-".into(),
        };
        println!(
            "{}  {:<22}  {:<16}  {}",
            dev.node.display(),
            usb,
            evidence,
            dev.name
        );
    }
    Ok(())
}

fn cmd_status() -> Result<(), Box<dyn std::error::Error>> {
    let response = daemon_request(Request::Status)?;
    print!("{response}");
    Ok(())
}

fn cmd_enroll(arg: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    require_root()?;
    let user = target_user(arg)?;
    let status = Backend::default().enroll(&user)?;
    if !status.success() {
        return Err("Howdy enrollment failed".into());
    }
    Ok(())
}

fn cmd_test(arg: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let user = target_user(arg)?;
    let response = daemon_request(Request::Authenticate {
        user,
        reason: "manual test".into(),
    })?;
    print!("{response}");
    if response.starts_with("OK\t") {
        Ok(())
    } else {
        Err("face verification failed".into())
    }
}

fn cmd_doctor() -> Result<(), Box<dyn std::error::Error>> {
    let mut failed = 0usize;
    let strict = strict_devices()?;
    check(
        "IR/depth hardware",
        !strict.is_empty(),
        &format!("{} strict device(s)", strict.len()),
        &mut failed,
    );
    check(
        "TPM 2.0",
        Path::new("/dev/tpmrm0").exists(),
        "/dev/tpmrm0",
        &mut failed,
    );
    let tpm_access = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tpmrm0")
        .is_ok();
    check(
        "TPM session access",
        tpm_access,
        "read/write /dev/tpmrm0 (tss group)",
        &mut failed,
    );
    check(
        "vhci_hcd",
        Path::new("/sys/module/vhci_hcd").exists(),
        "kernel module",
        &mut failed,
    );
    for group in ["irauth", "usbip", "tss"] {
        if group_exists(group) {
            check(
                &format!("group {group}"),
                active_group(group),
                "active in this login session",
                &mut failed,
            );
        }
    }

    let backend = Backend::default().preflight();
    check("Howdy command", backend.howdy, "howdy", &mut failed);
    check("pamtester", backend.pamtester, "pamtester", &mut failed);
    check(
        "dlib models",
        backend.missing_models.is_empty(),
        &if backend.missing_models.is_empty() {
            "ready".into()
        } else {
            backend.missing_models.join(", ")
        },
        &mut failed,
    );
    let camera = configured_camera()?;
    let (camera_ok, camera_detail) = match camera {
        Some(ref c) => (
            is_strict_device_path(&c.device_path)?,
            format!("{} ({})", c.device_path.display(), c.config_path.display()),
        ),
        None => (false, "Howdy device_path is missing/none".into()),
    };
    check("Howdy IR binding", camera_ok, &camera_detail, &mut failed);
    check(
        "IRAuth PAM module",
        pam_module_path().is_some(),
        "pam_irauth.so",
        &mut failed,
    );
    check(
        "Howdy-only PAM",
        Path::new("/etc/pam.d/irauth-howdy").is_file(),
        "/etc/pam.d/irauth-howdy",
        &mut failed,
    );
    check(
        "Passkey PAM",
        Path::new("/etc/pam.d/irauth-passkey").is_file(),
        "/etc/pam.d/irauth-passkey",
        &mut failed,
    );
    check(
        "daemon socket",
        Path::new(SOCKET_PATH).exists(),
        SOCKET_PATH,
        &mut failed,
    );
    let daemon_ok = daemon_request(Request::Ping)
        .map(|s| s.starts_with("PONG"))
        .unwrap_or(false);
    check("daemon protocol", daemon_ok, "V1", &mut failed);
    let passkey = irauth_passkey::diagnose();
    check(
        "passkey bridge",
        passkey.ready,
        &passkey.detail,
        &mut failed,
    );

    if failed == 0 {
        println!("\nIRAuth doctor: all checks passed");
        Ok(())
    } else {
        Err(format!("IRAuth doctor: {failed} check(s) failed").into())
    }
}

fn check(name: &str, ok: bool, detail: &str, failed: &mut usize) {
    println!("[{}] {:<22} {}", if ok { "OK" } else { "!!" }, name, detail);
    if !ok {
        *failed += 1;
    }
}

fn cmd_setup(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    require_root()?;
    let mut user: Option<String> = None;
    let mut camera: Option<PathBuf> = None;
    let mut with_login = false;
    let mut allow_no_tpm = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--user" => {
                i += 1;
                user = args.get(i).cloned();
                if user.is_none() {
                    return Err("--user requires a value".into());
                }
            }
            "--camera" => {
                i += 1;
                camera = args.get(i).map(PathBuf::from);
                if camera.is_none() {
                    return Err("--camera requires an absolute V4L2 path".into());
                }
            }
            "--with-login" => with_login = true,
            "--allow-no-tpm" => allow_no_tpm = true,
            other => return Err(format!("unknown setup option: {other}").into()),
        }
        i += 1;
    }
    let user = target_user(user.as_deref())?;
    println!("IRAuth setup for {user}");

    let strict = strict_devices()?;
    if strict.is_empty() {
        return Err(format!("no strict IR/depth camera detected; add a verified VID:PID to {VERIFIED_IDS_PATH} only after confirming the hardware is truly IR/depth").into());
    }
    for d in &strict {
        println!("  hardware: {} ({})", d.node.display(), d.name);
    }

    let selected_camera = select_camera(camera.as_deref(), &strict)?;
    println!("  selected IR camera: {}", selected_camera.display());

    if !Path::new("/dev/tpmrm0").exists() && !allow_no_tpm {
        return Err("TPM 2.0 is required by strict setup; use --allow-no-tpm only for PAM-only evaluation (passkeys stay disabled)".into());
    }

    if pam_module_path().is_none() {
        return Err(
            "pam_irauth.so is not installed; run the IRAuth installer/package before setup".into(),
        );
    }
    let backend = Backend::default();
    let mut pf = backend.preflight();
    if !pf.howdy {
        return Err("Howdy is not installed; IRAuth v0.1 deliberately uses Howdy as its recognition backend".into());
    }
    if !pf.pamtester {
        return Err("pamtester is not installed".into());
    }
    if pf.dlib_dir.is_some() {
        println!("  validating/repairing Howdy dlib model assets and permissions...");
        repair_dlib_assets()?;
        pf = backend.preflight();
    }
    if !pf.missing_models.is_empty() {
        return Err("Howdy dlib model repair did not complete".into());
    }

    if configured_camera()?
        .as_ref()
        .map(|c| c.device_path.as_path())
        != Some(selected_camera.as_path())
    {
        let config = bind_camera(&selected_camera)?;
        println!("  Howdy camera bound in {}", config.display());
    }
    if !is_strict_device_path(&selected_camera)? {
        return Err("selected camera stopped satisfying the strict IR/depth policy".into());
    }

    ensure_group("irauth")?;
    ensure_group("usbip")?;
    for group in ["irauth", "usbip", "tss"] {
        if group_exists(group) {
            add_user_to_group(&user, group)?;
        }
    }

    // Validate the recognition backend through an isolated PAM service before
    // touching any existing system PAM stack.
    install_howdy_only_pam()?;
    ensure_face_model(&backend, &user)?;
    test_howdy_path(&user)?;
    install_passkey_pam()?;

    write_modules_load()?;
    reload_udev()?;
    run_ok(Command::new("modprobe").arg("vhci-hcd"), "load vhci-hcd")?;
    apply_vhci_permissions()?;
    run_ok(
        Command::new("systemctl").arg("daemon-reload"),
        "systemd daemon-reload",
    )?;
    run_ok(
        Command::new("systemctl").args(["enable", "--now", "irauthd.service"]),
        "enable irauthd",
    )?;
    wait_for_daemon_ready()?;

    // Exercise the complete daemon path before routing an existing PAM service
    // through IRAuth. A failed validation leaves the host PAM configuration
    // untouched.
    println!("  verifying IRAuth daemon path; look at the IR camera...");
    let response = daemon_request(Request::Authenticate {
        user: user.clone(),
        reason: "setup validation".into(),
    })?;
    if !response.starts_with("OK\t") {
        return Err("face verification through irauthd failed".into());
    }

    // PAM changes are the lockout-sensitive part of setup. Snapshot the
    // pre-migration state so a failed transaction can be rolled back fully.
    let pam_snapshot = snapshot_pam_state()?;
    let mut selected_services = vec!["sudo"];
    if Path::new("/etc/pam.d/polkit-1").exists() {
        selected_services.push("polkit-1");
    }
    // `howdy-only` was an upstream bridge compatibility service. IRAuth-managed
    // passkeys now call irauth-passkey directly; leave this legacy service alone.
    if with_login && Path::new("/etc/pam.d/gdm-password").exists() {
        selected_services.push("gdm-password");
    }

    let pam_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let migrated = migrate_direct_howdy_pam(&selected_services)?;
        if migrated > 0 {
            println!("  migrated {migrated} selected Howdy PAM service(s) through IRAuth");
        }

        pam_enable("sudo")?;
        if Path::new("/etc/pam.d/polkit-1").exists() {
            pam_enable("polkit-1")?;
        }
        if with_login && Path::new("/etc/pam.d/gdm-password").exists() {
            pam_enable("gdm-password")?;
        }
        Ok(())
    })();

    if let Err(err) = pam_result {
        eprintln!("  PAM setup failed; restoring the pre-setup PAM configuration...");
        if let Err(rollback_err) = restore_pam_state(&pam_snapshot) {
            return Err(
                format!("PAM setup failed: {err}; rollback also failed: {rollback_err}").into(),
            );
        }
        return Err(err);
    }

    println!("\nSystem authentication is configured.");
    println!("IMPORTANT: log out completely and log back in once so irauth/usbip/tss group membership reaches your user session.");
    println!("After login run: irauthctl passkey adopt (if you already use howdy-as-passkey) or irauthctl passkey install, then irauthctl doctor");
    Ok(())
}

struct PamFileSnapshot {
    path: PathBuf,
    content: Vec<u8>,
    mode: u32,
}

struct PamSnapshot {
    pam_dir: PathBuf,
    manifest_path: PathBuf,
    files: Vec<PamFileSnapshot>,
    migrated_manifest: Option<PamFileSnapshot>,
}

fn snapshot_file(path: &Path) -> Result<PamFileSnapshot, Box<dyn std::error::Error>> {
    Ok(PamFileSnapshot {
        path: path.to_path_buf(),
        content: fs::read(path)?,
        mode: fs::metadata(path)?.permissions().mode() & 0o7777,
    })
}

fn snapshot_pam_state() -> Result<PamSnapshot, Box<dyn std::error::Error>> {
    snapshot_pam_state_in(
        Path::new("/etc/pam.d"),
        Path::new("/etc/irauth/pam-migrated.list"),
    )
}

fn snapshot_pam_state_in(
    pam_dir: &Path,
    manifest_path: &Path,
) -> Result<PamSnapshot, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(pam_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push(snapshot_file(&entry.path())?);
        }
    }

    let migrated_manifest = if manifest_path.is_file() {
        Some(snapshot_file(manifest_path)?)
    } else {
        None
    };

    Ok(PamSnapshot {
        pam_dir: pam_dir.to_path_buf(),
        manifest_path: manifest_path.to_path_buf(),
        files,
        migrated_manifest,
    })
}

fn restore_pam_state(snapshot: &PamSnapshot) -> Result<(), Box<dyn std::error::Error>> {
    let mut failures = Vec::new();

    for file in &snapshot.files {
        if let Err(err) = atomic_write(&file.path, &file.content, file.mode) {
            failures.push(format!("{}: {err}", file.path.display()));
        }
    }

    // Remove transaction artifacts that did not exist before setup. Existing
    // IRAuth backups are part of the snapshot and are preserved.
    if let Ok(entries) = fs::read_dir(&snapshot.pam_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let existed_before = snapshot.files.iter().any(|file| file.path == path);
            let is_transaction_artifact = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.ends_with(".irauth.bak")
                        || (name.contains(".irauth.") && name.ends_with(".tmp"))
                });
            if !existed_before && is_transaction_artifact {
                if let Err(err) = fs::remove_file(&path) {
                    failures.push(format!("{}: {err}", path.display()));
                }
            }
        }
    }

    let manifest_path = &snapshot.manifest_path;
    match &snapshot.migrated_manifest {
        Some(file) => {
            if let Err(err) = atomic_write(&file.path, &file.content, file.mode) {
                failures.push(format!("{}: {err}", file.path.display()));
            }
        }
        None if manifest_path.exists() => {
            if let Err(err) = fs::remove_file(manifest_path) {
                failures.push(format!("{}: {err}", manifest_path.display()));
            }
        }
        None => {}
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("PAM rollback was incomplete: {}", failures.join("; ")).into())
    }
}

fn select_camera(
    explicit: Option<&Path>,
    strict: &[irauth_hardware::VideoDevice],
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = explicit {
        if !path.is_absolute() {
            return Err("--camera must be an absolute path".into());
        }
        if !is_strict_device_path(path)? {
            return Err(format!("{} is not a strict IR/depth camera", path.display()).into());
        }
        return Ok(path.to_path_buf());
    }
    if let Some(current) = configured_camera()? {
        if is_strict_device_path(&current.device_path)? {
            return Ok(current.device_path);
        }
    }
    if strict.len() == 1 {
        return Ok(strict[0].node.clone());
    }
    Err("multiple strict IR/depth nodes detected and Howdy is not already bound to one; rerun setup with --camera /dev/videoN".into())
}

fn cmd_pam(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    require_root()?;
    match (
        args.first().map(String::as_str),
        args.get(1).map(String::as_str),
    ) {
        (Some("enable"), Some(service)) => pam_enable(service),
        (Some("disable"), Some(service)) => pam_disable(service),
        _ => Err("usage: irauthctl pam enable|disable SERVICE".into()),
    }
}

fn pam_enable(service: &str) -> Result<(), Box<dyn std::error::Error>> {
    validate_service_name(service)?;
    let path = PathBuf::from("/etc/pam.d").join(service);
    require_regular_file(&path)?;
    let content = fs::read_to_string(&path)?;
    if content.lines().any(|l| l.contains("pam_irauth.so")) {
        println!("  PAM {service}: already enabled");
        return Ok(());
    }
    let backup = pam_backup_path(&path);
    create_backup_once(&path, &backup)?;
    let stanza = "# IRAuth begin\nauth sufficient pam_irauth.so reason=system\n# IRAuth end\n";
    let mut out = String::new();
    let mut inserted = false;
    for line in content.lines() {
        out.push_str(line);
        out.push('\n');
        if !inserted && line.trim_start().starts_with("#%PAM") {
            out.push_str(stanza);
            inserted = true;
        }
    }
    if !inserted {
        out = format!("{stanza}{out}");
    }
    let mode = fs::metadata(&path)?.permissions().mode() & 0o7777;
    atomic_write(&path, out.as_bytes(), mode)?;
    println!("  PAM {service}: enabled (backup {})", backup.display());
    Ok(())
}

fn pam_disable(service: &str) -> Result<(), Box<dyn std::error::Error>> {
    validate_service_name(service)?;
    let path = PathBuf::from("/etc/pam.d").join(service);
    require_regular_file(&path)?;
    let backup = pam_backup_path(&path);
    if backup.exists() || fs::symlink_metadata(&backup).is_ok() {
        require_regular_file(&backup)?;
        let mode = fs::metadata(&backup)?.permissions().mode() & 0o7777;
        atomic_write(&path, &fs::read(&backup)?, mode)?;
        println!("  PAM {service}: restored {}", backup.display());
        return Ok(());
    }
    let content = fs::read_to_string(&path)?;
    let mut out = String::new();
    let mut skip = false;
    for line in content.lines() {
        if line.trim() == "# IRAuth begin" {
            skip = true;
            continue;
        }
        if line.trim() == "# IRAuth end" {
            skip = false;
            continue;
        }
        if !skip {
            out.push_str(line);
            out.push('\n');
        }
    }
    let mode = fs::metadata(&path)?.permissions().mode() & 0o7777;
    atomic_write(&path, out.as_bytes(), mode)?;
    Ok(())
}

fn install_howdy_only_pam() -> Result<(), Box<dyn std::error::Error>> {
    let line = discover_howdy_pam_line().ok_or("could not discover an existing Howdy PAM auth line; configure Howdy for at least one PAM service first")?;
    let content = format!("#%PAM-1.0\n# Generated by IRAuth. Face-only backend; do not add password fallback here.\n{line}\nauth required pam_deny.so\n");
    atomic_write(
        Path::new("/etc/pam.d/irauth-howdy"),
        content.as_bytes(),
        0o644,
    )?;
    Ok(())
}

fn migrate_direct_howdy_pam(
    selected_services: &[&str],
) -> Result<usize, Box<dyn std::error::Error>> {
    migrate_direct_howdy_pam_in(Path::new("/etc/pam.d"), selected_services)
}

fn migrate_direct_howdy_pam_in(
    pam_dir: &Path,
    selected_services: &[&str],
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut migrated = Vec::<PathBuf>::new();
    for entry in fs::read_dir(pam_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with("irauth-") || name.ends_with(".irauth.bak") {
            continue;
        }
        if !selected_services.contains(&name) || !entry.file_type()?.is_file() {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let (out, found) = rewrite_direct_howdy_pam(&content);
        if !found {
            continue;
        }
        let backup = pam_backup_path(&path);
        create_backup_once(&path, &backup)?;
        let mode = fs::metadata(&path)?.permissions().mode() & 0o7777;
        atomic_write(&path, out.as_bytes(), mode)?;
        migrated.push(path);
    }
    refresh_migration_manifest_in(
        pam_dir,
        &pam_dir
            .parent()
            .unwrap_or(pam_dir)
            .join("irauth/pam-migrated.list"),
    )?;
    Ok(migrated.len())
}

fn rewrite_direct_howdy_pam(content: &str) -> (String, bool) {
    let mut found = false;
    let mut inserted = false;
    let mut out = String::new();
    for line in content.lines() {
        let t = line.trim();
        let lower = t.to_ascii_lowercase();
        let direct_howdy = !t.starts_with('#') && t.starts_with("auth ") && lower.contains("howdy");
        if direct_howdy {
            found = true;
            out.push_str(
                "# IRAuth disabled direct Howdy PAM entry to enforce strict camera policy:\n# ",
            );
            out.push_str(line);
            out.push('\n');
            if !inserted {
                out.push_str("auth sufficient pam_irauth.so reason=system\n");
                inserted = true;
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    (out, found)
}

fn refresh_migration_manifest_in(
    pam_dir: &Path,
    manifest_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let marker = "# IRAuth disabled direct Howdy PAM entry to enforce strict camera policy:";
    let mut migrated = Vec::<PathBuf>::new();

    for entry in fs::read_dir(pam_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with(".irauth.bak") || (name.contains(".irauth.") && name.ends_with(".tmp")) {
            continue;
        }
        if fs::read_to_string(&path)
            .map(|content| content.contains(marker))
            .unwrap_or(false)
        {
            migrated.push(path);
        }
    }

    migrated.sort();
    if migrated.is_empty() {
        if manifest_path.exists() {
            fs::remove_file(manifest_path)?;
        }
        return Ok(());
    }

    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut manifest = String::new();
    for path in migrated {
        manifest.push_str(&path.to_string_lossy());
        manifest.push('\n');
    }
    atomic_write(manifest_path, manifest.as_bytes(), 0o600)
}

fn install_passkey_pam() -> Result<(), Box<dyn std::error::Error>> {
    let content = "#%PAM-1.0\n# Generated by IRAuth.\nauth sufficient pam_irauth.so reason=passkey\nauth required pam_deny.so\n";
    atomic_write(
        Path::new("/etc/pam.d/irauth-passkey"),
        content.as_bytes(),
        0o644,
    )?;
    Ok(())
}

fn discover_howdy_pam_line() -> Option<String> {
    let dir = fs::read_dir("/etc/pam.d").ok()?;
    for entry in dir.flatten() {
        let path = entry.path();
        if !path.is_file() || path.ends_with("irauth-howdy") {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines() {
            let t = line.trim();
            let lower = t.to_ascii_lowercase();
            if t.starts_with("auth ") && lower.contains("howdy") && !t.starts_with('#') {
                return Some(t.to_owned());
            }
        }
    }
    None
}

fn ensure_face_model(backend: &Backend, user: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("howdy")
        .arg("-U")
        .arg(user)
        .arg("list")
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    println!("  no Howdy model for {user}; starting enrollment...");
    let status = backend.enroll(user)?;
    if !status.success() {
        return Err("Howdy face enrollment failed".into());
    }
    Ok(())
}

fn test_howdy_path(user: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("  verifying dedicated Howdy PAM path; look at the IR camera...");
    let status = Command::new("pamtester")
        .args(["irauth-howdy", user, "authenticate"])
        .status()?;
    if !status.success() {
        return Err("face verification through irauth-howdy failed".into());
    }
    Ok(())
}

fn ensure_group(group: &str) -> Result<(), Box<dyn std::error::Error>> {
    if group_exists(group) {
        return Ok(());
    }
    run_ok(
        Command::new("groupadd").args(["--system", group]),
        &format!("create {group} group"),
    )
}

fn group_exists(group: &str) -> bool {
    Command::new("getent")
        .args(["group", group])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn active_group(group: &str) -> bool {
    Command::new("id")
        .arg("-nG")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .any(|g| g == group)
        })
        .unwrap_or(false)
}

fn add_user_to_group(user: &str, group: &str) -> Result<(), Box<dyn std::error::Error>> {
    run_ok(
        Command::new("usermod").args(["-aG", group, user]),
        &format!("add {user} to {group}"),
    )
}

fn write_modules_load() -> Result<(), Box<dyn std::error::Error>> {
    atomic_write(
        Path::new("/etc/modules-load.d/irauth-vhci.conf"),
        b"vhci-hcd\n",
        0o644,
    )
}

fn reload_udev() -> Result<(), Box<dyn std::error::Error>> {
    run_ok(
        Command::new("udevadm").args(["control", "--reload"]),
        "reload udev",
    )?;
    Ok(())
}

fn apply_vhci_permissions() -> Result<(), Box<dyn std::error::Error>> {
    let base = Path::new("/sys/devices/platform/vhci_hcd.0");
    let attach = base.join("attach");
    let detach = base.join("detach");
    if attach.exists() && detach.exists() {
        run_ok(
            Command::new("chgrp").arg("usbip").arg(&attach).arg(&detach),
            "set vhci group",
        )?;
        run_ok(
            Command::new("chmod").arg("0660").arg(&attach).arg(&detach),
            "set vhci permissions",
        )?;
    }
    Ok(())
}

fn wait_for_daemon_ready() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_daemon_ready_with(
        || daemon_request(Request::Ping),
        Duration::from_secs(5),
        Duration::from_millis(100),
    )
}

fn wait_for_daemon_ready_with<F>(
    mut probe: F,
    timeout: Duration,
    interval: Duration,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut() -> io::Result<String>,
{
    let started = std::time::Instant::now();
    let last_error = loop {
        let error = match probe() {
            Ok(response) if response.starts_with("PONG") => return Ok(()),
            Ok(response) => format!("unexpected daemon response: {}", response.trim()),
            Err(err) => err.to_string(),
        };
        if started.elapsed() >= timeout {
            break error;
        }
        std::thread::sleep(interval.min(timeout.saturating_sub(started.elapsed())));
    };

    Err(format!(
        "irauthd did not become ready within {:.1} seconds: {last_error}",
        timeout.as_secs_f32()
    )
    .into())
}

fn daemon_request(req: Request) -> io::Result<String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)?;
    stream.set_read_timeout(Some(Duration::from_secs(35)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(encode_request(&req).as_bytes())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(line)
}

fn target_user(explicit: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(user) = explicit {
        return validate_user(user).map(str::to_owned);
    }
    if let Ok(user) = env::var("SUDO_USER") {
        if user != "root" {
            return validate_user(&user).map(str::to_owned);
        }
    }
    let user = env::var("USER").unwrap_or_default();
    validate_user(&user).map(str::to_owned)
}

fn validate_user(user: &str) -> Result<&str, Box<dyn std::error::Error>> {
    if user.is_empty()
        || !user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err("invalid user name".into());
    }
    Ok(user)
}

fn create_backup_once(source: &Path, backup: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    require_regular_file(source)?;
    let metadata = fs::metadata(source)?;
    let mut target = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(metadata.permissions().mode() & 0o7777)
        .open(backup)
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            require_regular_file(backup)?;
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let result = (|| -> io::Result<()> {
        target.write_all(&fs::read(source)?)?;
        target.sync_all()?;
        fs::set_permissions(backup, metadata.permissions())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(backup);
    }
    result?;
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(format!("refusing non-regular PAM path: {}", path.display()).into());
    }
    Ok(())
}

fn pam_backup_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.irauth.bak", path.display()))
}

fn validate_service_name(service: &str) -> Result<(), Box<dyn std::error::Error>> {
    if service.is_empty()
        || !service
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err("invalid PAM service name".into());
    }
    Ok(())
}

fn require_root() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { geteuid() } != 0 {
        Err("this command must run as root".into())
    } else {
        Ok(())
    }
}

fn pam_module_path() -> Option<PathBuf> {
    [
        "/usr/lib64/security/pam_irauth.so",
        "/usr/lib/x86_64-linux-gnu/security/pam_irauth.so",
        "/lib/security/pam_irauth.so",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

fn run_ok(cmd: &mut Command, what: &str) -> Result<(), Box<dyn std::error::Error>> {
    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what} failed with {status}").into())
    }
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("irauth.{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    let result = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path =
                env::temp_dir().join(format!("irauthctl-test-{}-{nonce}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn setup_test_tree() -> (TempDir, PathBuf, PathBuf) {
        let root = TempDir::new();
        let pam = root.0.join("pam.d");
        let manifest = root.0.join("irauth/pam-migrated.list");
        fs::create_dir_all(&pam).unwrap();
        (root, pam, manifest)
    }

    #[test]
    fn migration_only_changes_selected_services_and_leaves_unselected_login_stack_untouched() {
        let (_root, pam, manifest) = setup_test_tree();
        let sudo = b"#%PAM-1.0\nauth sufficient pam_howdy.so\nauth include system-auth\n";
        let unrelated = b"#%PAM-1.0\nauth required pam_unix.so\n";
        let gdm = b"#%PAM-1.0\nauth sufficient pam_howdy.so\nauth substack password-auth\n";
        fs::write(pam.join("sudo"), sudo).unwrap();
        fs::write(pam.join("other"), unrelated).unwrap();
        fs::write(pam.join("gdm-password"), gdm).unwrap();

        assert_eq!(migrate_direct_howdy_pam_in(&pam, &["sudo"]).unwrap(), 1);
        assert_eq!(fs::read(pam.join("other")).unwrap(), unrelated);
        assert_eq!(fs::read(pam.join("gdm-password")).unwrap(), gdm);
        let migrated = fs::read_to_string(pam.join("sudo")).unwrap();
        assert!(migrated.contains("# auth sufficient pam_howdy.so"));
        assert_eq!(migrated.matches("pam_irauth.so").count(), 1);
        assert_eq!(
            fs::read_to_string(&manifest).unwrap(),
            format!("{}\n", pam.join("sudo").display())
        );
    }

    #[test]
    fn migration_is_idempotent_and_never_overwrites_existing_backup() {
        let (_root, pam, manifest) = setup_test_tree();
        let service = pam.join("sudo");
        let backup = pam_backup_path(&service);
        fs::write(&service, "#%PAM-1.0\nauth sufficient pam_howdy.so\n").unwrap();
        fs::write(&backup, b"preserve backup").unwrap();
        assert_eq!(migrate_direct_howdy_pam_in(&pam, &["sudo"]).unwrap(), 1);
        let first = fs::read(&service).unwrap();
        assert_eq!(migrate_direct_howdy_pam_in(&pam, &["sudo"]).unwrap(), 0);
        assert_eq!(fs::read(&service).unwrap(), first);
        assert_eq!(fs::read(backup).unwrap(), b"preserve backup");
        assert_eq!(fs::read_to_string(manifest).unwrap().lines().count(), 1);
    }

    #[test]
    fn empty_migration_removes_stale_manifest() {
        let (_root, pam, manifest) = setup_test_tree();
        fs::write(pam.join("sudo"), "#%PAM-1.0\nauth required pam_unix.so\n").unwrap();
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(&manifest, "/stale\n").unwrap();
        migrate_direct_howdy_pam_in(&pam, &["sudo"]).unwrap();
        assert!(!manifest.exists());
    }

    #[test]
    fn rollback_restores_content_mode_manifest_and_removes_new_artifacts() {
        let (_root, pam, manifest) = setup_test_tree();
        let service = pam.join("sudo");
        fs::write(&service, "original\n").unwrap();
        fs::set_permissions(&service, fs::Permissions::from_mode(0o640)).unwrap();
        let snapshot = snapshot_pam_state_in(&pam, &manifest).unwrap();
        fs::write(&service, "changed\n").unwrap();
        fs::write(pam.join("sudo.irauth.bak"), "new backup").unwrap();
        fs::write(pam.join("sudo.irauth.123.tmp"), "new temp").unwrap();
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(&manifest, "new manifest\n").unwrap();
        restore_pam_state(&snapshot).unwrap();
        assert_eq!(fs::read(&service).unwrap(), b"original\n");
        assert_eq!(
            fs::metadata(service).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(!pam.join("sudo.irauth.bak").exists());
        assert!(!pam.join("sudo.irauth.123.tmp").exists());
        assert!(!manifest.exists());
    }

    #[test]
    fn rollback_preserves_preexisting_transaction_artifacts_and_restores_manifest() {
        let (_root, pam, manifest) = setup_test_tree();
        let service = pam.join("sudo");
        let old_backup = pam.join("sudo.irauth.bak");
        fs::write(&service, "original\n").unwrap();
        fs::write(&old_backup, "old backup").unwrap();
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(&manifest, "old manifest\n").unwrap();
        let snapshot = snapshot_pam_state_in(&pam, &manifest).unwrap();
        fs::write(&service, "changed\n").unwrap();
        fs::write(&old_backup, "changed backup").unwrap();
        fs::write(&manifest, "new manifest\n").unwrap();
        restore_pam_state(&snapshot).unwrap();
        assert_eq!(fs::read(old_backup).unwrap(), b"old backup");
        assert_eq!(fs::read_to_string(manifest).unwrap(), "old manifest\n");
    }

    #[test]
    fn readiness_retries_connection_errors_until_pong_and_reports_last_error() {
        let mut attempts = 0;
        wait_for_daemon_ready_with(
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "not listening",
                    ))
                } else {
                    Ok("PONG\\n".into())
                }
            },
            Duration::from_millis(50),
            Duration::from_millis(1),
        )
        .unwrap();
        assert_eq!(attempts, 3);

        let err = wait_for_daemon_ready_with(
            || Err(io::Error::new(io::ErrorKind::NotFound, "socket missing")),
            Duration::from_millis(2),
            Duration::from_millis(1),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("within 0.0 seconds"));
        assert!(err.contains("socket missing"));
    }
}

#[allow(dead_code)]
fn output_text(output: &Output) -> String {
    let mut s = String::from_utf8_lossy(&output.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&output.stderr));
    s
}
