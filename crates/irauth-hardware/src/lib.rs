use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const VERIFIED_IDS_PATH: &str = "/etc/irauth/hardware.ids";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    IrName,
    DepthName,
    VerifiedUsbId,
    None,
}

impl Evidence {
    pub fn is_strict(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoDevice {
    pub node: PathBuf,
    pub name: String,
    pub usb_id: Option<String>,
    pub evidence: Evidence,
}

pub fn probe() -> io::Result<Vec<VideoDevice>> {
    probe_at(Path::new("/sys/class/video4linux"), Path::new(VERIFIED_IDS_PATH))
}

pub fn strict_devices() -> io::Result<Vec<VideoDevice>> {
    Ok(probe()?.into_iter().filter(|d| d.evidence.is_strict()).collect())
}

/// Resolve a configured V4L2 path (including /dev/v4l/by-path symlinks) and
/// return the strict device it identifies. A missing/unresolvable device is not
/// accepted: callers should fail closed rather than fall back to another camera.
pub fn strict_device_for_path(path: &Path) -> io::Result<Option<VideoDevice>> {
    let configured = match fs::canonicalize(path) {
        Ok(path) => path,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    for device in strict_devices()? {
        if let Ok(node) = fs::canonicalize(&device.node) {
            if node == configured {
                return Ok(Some(device));
            }
        }
    }
    Ok(None)
}

pub fn is_strict_device_path(path: &Path) -> io::Result<bool> {
    Ok(strict_device_for_path(path)?.is_some())
}

pub fn probe_at(sys_root: &Path, verified_ids_path: &Path) -> io::Result<Vec<VideoDevice>> {
    let verified = read_verified_ids(verified_ids_path).unwrap_or_default();
    let mut devices = Vec::new();
    if !sys_root.exists() {
        return Ok(devices);
    }
    for entry in fs::read_dir(sys_root)? {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !file_name.starts_with("video") {
            continue;
        }
        let base = entry.path();
        let name = read_trimmed(base.join("name")).unwrap_or_else(|| file_name.clone());
        let usb_id = find_usb_id(&base);
        let lower = name.to_ascii_lowercase();
        let evidence = if lower.contains("infrared") || token_ir(&lower) {
            Evidence::IrName
        } else if lower.contains("depth") || lower.contains("3d camera") {
            Evidence::DepthName
        } else if usb_id.as_ref().is_some_and(|id| verified.contains(id)) {
            Evidence::VerifiedUsbId
        } else {
            Evidence::None
        };
        devices.push(VideoDevice {
            node: PathBuf::from("/dev").join(file_name),
            name,
            usb_id,
            evidence,
        });
    }
    devices.sort_by(|a, b| a.node.cmp(&b.node));
    Ok(devices)
}

fn token_ir(lower: &str) -> bool {
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|part| part == "ir")
}

fn read_trimmed(path: PathBuf) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

fn read_verified_ids(path: &Path) -> io::Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for line in fs::read_to_string(path)?.lines() {
        let line = line.split('#').next().unwrap_or("").trim().to_ascii_lowercase();
        if valid_usb_id(&line) {
            ids.insert(line);
        }
    }
    Ok(ids)
}

fn valid_usb_id(s: &str) -> bool {
    let Some((vid, pid)) = s.split_once(':') else { return false };
    vid.len() == 4
        && pid.len() == 4
        && vid.chars().chain(pid.chars()).all(|c| c.is_ascii_hexdigit())
}

fn find_usb_id(video_class: &Path) -> Option<String> {
    let mut cur = fs::canonicalize(video_class.join("device")).ok()?;
    loop {
        let vid = read_trimmed(cur.join("idVendor"));
        let pid = read_trimmed(cur.join("idProduct"));
        if let (Some(vid), Some(pid)) = (vid, pid) {
            let id = format!("{}:{}", vid.to_ascii_lowercase(), pid.to_ascii_lowercase());
            if valid_usb_id(&id) {
                return Some(id);
            }
        }
        if !cur.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("irauth-hw-{n}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn ir_name_is_strict() {
        let root = temp_dir();
        let v = root.join("video0");
        fs::create_dir_all(&v).unwrap();
        fs::write(v.join("name"), "Integrated IR Camera\n").unwrap();
        let ids = root.join("ids");
        fs::write(&ids, "").unwrap();
        let devices = probe_at(&root, &ids).unwrap();
        assert_eq!(devices[0].evidence, Evidence::IrName);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn rgb_name_is_not_accepted() {
        let root = temp_dir();
        let v = root.join("video0");
        fs::create_dir_all(&v).unwrap();
        fs::write(v.join("name"), "HD Webcam\n").unwrap();
        let ids = root.join("ids");
        fs::write(&ids, "").unwrap();
        let devices = probe_at(&root, &ids).unwrap();
        assert_eq!(devices[0].evidence, Evidence::None);
        fs::remove_dir_all(root).ok();
    }
}
