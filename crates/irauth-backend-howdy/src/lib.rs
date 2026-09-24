use irauth_core::HOWDY_PAM_SERVICE;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const REQUIRED_DLIB_MODELS: &[&str] = &[
    "dlib_face_recognition_resnet_model_v1.dat",
    "mmod_human_face_detector.dat",
    "shape_predictor_5_face_landmarks.dat",
];

const HOWDY_CONFIGS: &[&str] = &[
    "/usr/local/etc/howdy/config.ini",
    "/etc/howdy/config.ini",
    "/lib/security/howdy/config.ini",
    "/usr/lib/security/howdy/config.ini",
    "/usr/lib64/howdy/config.ini",
    "/usr/local/lib64/howdy/config.ini",
];

const DLIB_DIRS: &[&str] = &[
    "/usr/local/share/dlib-data",
    "/usr/share/dlib-data",
    "/lib/security/howdy/dlib-data",
    "/usr/lib/security/howdy/dlib-data",
];

#[derive(Debug, Clone)]
pub struct Backend {
    pam_service: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preflight {
    pub howdy: bool,
    pub pamtester: bool,
    pub dlib_dir: Option<PathBuf>,
    pub missing_models: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub approved: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraConfig {
    pub config_path: PathBuf,
    pub device_path: PathBuf,
}

impl Default for Backend {
    fn default() -> Self {
        Self::new(HOWDY_PAM_SERVICE)
    }
}

impl Backend {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            pam_service: service.into(),
        }
    }

    pub fn preflight(&self) -> Preflight {
        let dlib_dir = find_dlib_dir();
        let missing_models = dlib_dir.as_deref().map(missing_models).unwrap_or_else(|| {
            REQUIRED_DLIB_MODELS
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        });
        Preflight {
            howdy: command_exists("howdy"),
            pamtester: command_exists("pamtester"),
            dlib_dir,
            missing_models,
        }
    }

    pub fn authenticate(&self, user: &str, reason: &str) -> io::Result<AuthResult> {
        if !valid_username(user) {
            return Ok(AuthResult {
                approved: false,
                detail: "invalid user name".into(),
            });
        }
        let mut child = Command::new("pamtester")
            .arg(&self.pam_service)
            .arg(user)
            .arg("authenticate")
            .env("IRAUTH_REASON", reason)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let started = Instant::now();
        loop {
            if child.try_wait()?.is_some() {
                let output = child.wait_with_output()?;
                let detail = combined_output(&output.stdout, &output.stderr);
                return Ok(AuthResult {
                    approved: output.status.success(),
                    detail,
                });
            }
            if started.elapsed() >= authentication_timeout_hint() {
                let _ = child.kill();
                let output = child.wait_with_output()?;
                let mut detail = combined_output(&output.stdout, &output.stderr);
                if !detail.is_empty() {
                    detail.push_str(" | ");
                }
                detail.push_str("IRAuth backend timeout after 30s");
                return Ok(AuthResult {
                    approved: false,
                    detail,
                });
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn enroll(&self, user: &str) -> io::Result<ExitStatus> {
        Command::new("howdy")
            .arg("-U")
            .arg(user)
            .arg("add")
            .status()
    }

    pub fn list(&self, user: &str) -> io::Result<ExitStatus> {
        Command::new("howdy")
            .arg("-U")
            .arg(user)
            .arg("list")
            .status()
    }
}

pub fn find_howdy_config() -> Option<PathBuf> {
    HOWDY_CONFIGS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

pub fn configured_camera() -> io::Result<Option<CameraConfig>> {
    let Some(config_path) = find_howdy_config() else {
        return Ok(None);
    };
    let content = fs::read_to_string(&config_path)?;
    let Some(device) = parse_video_device_path(&content) else {
        return Ok(None);
    };
    if device.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    Ok(Some(CameraConfig {
        config_path,
        device_path: PathBuf::from(device),
    }))
}

/// Bind Howdy's [video] device_path to an already-validated IR/depth V4L2
/// node. The caller is responsible for enforcing the hardware policy first.
pub fn bind_camera(device: &Path) -> io::Result<PathBuf> {
    if !device.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "camera path must be absolute",
        ));
    }
    let config = find_howdy_config()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Howdy config.ini not found"))?;
    let content = fs::read_to_string(&config)?;
    let updated = replace_video_device_path(&content, &device.to_string_lossy())?;
    let backup = PathBuf::from(format!("{}.irauth.bak", config.display()));
    if !backup.exists() {
        fs::copy(&config, &backup)?;
    }
    let metadata = fs::metadata(&config)?;
    let tmp = PathBuf::from(format!("{}.irauth.tmp", config.display()));
    fs::write(&tmp, updated)?;
    fs::set_permissions(&tmp, metadata.permissions())?;
    fs::rename(&tmp, &config)?;
    Ok(config)
}

pub fn find_dlib_dir() -> Option<PathBuf> {
    DLIB_DIRS.iter().map(PathBuf::from).find(|p| p.exists())
}

pub fn missing_models(dir: &Path) -> Vec<String> {
    REQUIRED_DLIB_MODELS
        .iter()
        .filter(|name| !dir.join(name).is_file())
        .map(|name| (*name).to_owned())
        .collect()
}

pub fn repair_dlib_assets() -> io::Result<()> {
    let dir = find_dlib_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Howdy dlib-data directory not found",
        )
    })?;
    let mut perms = fs::metadata(&dir)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        fs::set_permissions(&dir, perms)?;
    }
    if missing_models(&dir).is_empty() {
        normalize_model_permissions(&dir)?;
        return Ok(());
    }
    let installer = dir.join("install.sh");
    if !installer.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing dlib models and installer: {}", installer.display()),
        ));
    }
    let status = Command::new("/bin/bash")
        .arg(&installer)
        .current_dir(&dir)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("{} failed", installer.display())));
    }
    let missing = missing_models(&dir);
    if !missing.is_empty() {
        return Err(io::Error::other(format!(
            "dlib installer completed but models are still missing: {}",
            missing.join(", ")
        )));
    }
    normalize_model_permissions(&dir)
}

fn normalize_model_permissions(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for model in REQUIRED_DLIB_MODELS {
            let path = dir.join(model);
            if path.exists() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
            }
        }
    }
    Ok(())
}

fn parse_video_device_path(content: &str) -> Option<String> {
    let mut in_video = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_video = line[1..line.len() - 1].trim().eq_ignore_ascii_case("video");
            continue;
        }
        if !in_video {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("device_path") {
            let value = value.split(['#', ';']).next().unwrap_or("").trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn replace_video_device_path(content: &str, device: &str) -> io::Result<String> {
    let mut out = Vec::<String>::new();
    let mut in_video = false;
    let mut saw_video = false;
    let mut replaced = false;
    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_video && !replaced {
                out.push(format!("device_path = {device}"));
                replaced = true;
            }
            in_video = trimmed[1..trimmed.len() - 1]
                .trim()
                .eq_ignore_ascii_case("video");
            saw_video |= in_video;
            out.push(raw.to_owned());
            continue;
        }
        if in_video {
            if let Some((key, _)) = trimmed.split_once('=') {
                if key.trim().eq_ignore_ascii_case("device_path") {
                    out.push(format!("device_path = {device}"));
                    replaced = true;
                    continue;
                }
            }
        }
        out.push(raw.to_owned());
    }
    if !saw_video {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Howdy config has no [video] section",
        ));
    }
    if !replaced {
        out.push(format!("device_path = {device}"));
    }
    let mut result = out.join("\n");
    result.push('\n');
    Ok(result)
}

fn command_exists(command: &str) -> bool {
    if command.contains('/') {
        return Path::new(command).is_file();
    }
    env::var_os("PATH")
        .map(|path| env::split_paths(&path).any(|dir| dir.join(command).is_file()))
        .unwrap_or(false)
}

fn combined_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(stdout).trim().to_owned();
    let e = String::from_utf8_lossy(stderr).trim().to_owned();
    if !e.is_empty() {
        if !s.is_empty() {
            s.push_str(" | ");
        }
        s.push_str(&e);
    }
    if s.len() > 512 {
        s.truncate(512);
    }
    s
}

fn valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

pub fn authentication_timeout_hint() -> Duration {
    Duration::from_secs(30)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_validation_is_conservative() {
        assert!(valid_username("alice-1"));
        assert!(!valid_username("../root"));
        assert!(!valid_username("a b"));
    }

    #[test]
    fn parses_howdy_video_device() {
        let ini = "[core]\ndetection_notice = false\n[video]\ndevice_path = /dev/video2 # IR\n";
        assert_eq!(parse_video_device_path(ini).as_deref(), Some("/dev/video2"));
    }

    #[test]
    fn rewrites_howdy_video_device() {
        let ini = "[video]\nfoo = bar\ndevice_path = /dev/video0\n[core]\nx = y\n";
        let got = replace_video_device_path(ini, "/dev/video2").unwrap();
        assert!(got.contains("device_path = /dev/video2"));
        assert!(!got.contains("device_path = /dev/video0"));
    }
}
