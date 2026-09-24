use irauth_core::HOWDY_PAM_SERVICE;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

const REQUIRED_DLIB_MODELS: &[&str] = &[
    "dlib_face_recognition_resnet_model_v1.dat",
    "mmod_human_face_detector.dat",
    "shape_predictor_5_face_landmarks.dat",
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

impl Default for Backend {
    fn default() -> Self {
        Self::new(HOWDY_PAM_SERVICE)
    }
}

impl Backend {
    pub fn new(service: impl Into<String>) -> Self {
        Self { pam_service: service.into() }
    }

    pub fn preflight(&self) -> Preflight {
        let dlib_dir = find_dlib_dir();
        let missing_models = dlib_dir
            .as_deref()
            .map(missing_models)
            .unwrap_or_else(|| REQUIRED_DLIB_MODELS.iter().map(|s| (*s).to_owned()).collect());
        Preflight {
            howdy: command_exists("howdy"),
            pamtester: command_exists("pamtester"),
            dlib_dir,
            missing_models,
        }
    }

    pub fn authenticate(&self, user: &str, reason: &str) -> io::Result<AuthResult> {
        if !valid_username(user) {
            return Ok(AuthResult { approved: false, detail: "invalid user name".into() });
        }
        let output = Command::new("pamtester")
            .arg(&self.pam_service)
            .arg(user)
            .arg("authenticate")
            .env("IRAUTH_REASON", reason)
            .stdin(Stdio::null())
            .output()?;
        let detail = combined_output(&output.stdout, &output.stderr);
        Ok(AuthResult {
            approved: output.status.success(),
            detail,
        })
    }

    pub fn enroll(&self, user: &str) -> io::Result<ExitStatus> {
        Command::new("howdy").arg("-U").arg(user).arg("add").status()
    }

    pub fn list(&self, user: &str) -> io::Result<ExitStatus> {
        Command::new("howdy").arg("-U").arg(user).arg("list").status()
    }
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
    let dir = find_dlib_dir().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Howdy dlib-data directory not found"))?;
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
    let status = Command::new("/bin/bash").arg(&installer).current_dir(&dir).status()?;
    if !status.success() {
        return Err(io::Error::other(format!("{} failed", installer.display())));
    }
    let missing = missing_models(&dir);
    if !missing.is_empty() {
        return Err(io::Error::other(format!("dlib installer completed but models are still missing: {}", missing.join(", "))));
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
        if !s.is_empty() { s.push_str(" | "); }
        s.push_str(&e);
    }
    if s.len() > 512 { s.truncate(512); }
    s
}

fn valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
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
}
