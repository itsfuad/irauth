use irauth_backend_howdy::{configured_camera, Backend};
use irauth_core::{
    decode_request, encode_response, DaemonStatus, Request, Response, SOCKET_GROUP, SOCKET_PATH,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SOL_SOCKET: c_int = 1;
const SO_PEERCRED: c_int = 17;
const MIN_REQUEST_INTERVAL: Duration = Duration::from_millis(500);
const REQUEST_WORKERS: usize = 4;
const REQUEST_QUEUE: usize = 16;
const MAX_REQUEST_BYTES: u64 = 1024;

#[repr(C)]
struct UCred {
    _pid: c_int,
    uid: u32,
    _gid: u32,
}

extern "C" {
    fn getsockopt(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *mut c_void,
        optlen: *mut u32,
    ) -> c_int;
    fn chown(path: *const c_char, owner: u32, group: u32) -> c_int;
}

struct State {
    backend: Backend,
    camera_lock: Mutex<()>,
    rate_limit: Mutex<HashMap<u32, Instant>>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("irauthd: {err}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let socket = Path::new(SOCKET_PATH);
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
    }
    if socket.exists() {
        fs::remove_file(socket)?;
    }
    let listener = UnixListener::bind(socket)?;
    secure_socket(socket)?;

    let state = Arc::new(State {
        backend: Backend::default(),
        camera_lock: Mutex::new(()),
        rate_limit: Mutex::new(HashMap::new()),
    });

    let (sender, receiver) = std::sync::mpsc::sync_channel::<UnixStream>(REQUEST_QUEUE);
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..REQUEST_WORKERS {
        let receiver = Arc::clone(&receiver);
        let state = Arc::clone(&state);
        thread::spawn(move || loop {
            let stream = match receiver.lock() {
                Ok(receiver) => receiver.recv(),
                Err(_) => return,
            };
            match stream {
                Ok(stream) => {
                    if let Err(err) = handle(stream, &state) {
                        eprintln!("irauthd: request failed: {err}");
                    }
                }
                Err(_) => return,
            }
        });
    }

    eprintln!("irauthd: listening on {SOCKET_PATH}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => match sender.try_send(stream) {
                Ok(()) => {}
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    eprintln!("irauthd: request queue full; dropping connection");
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "request workers stopped",
                    ));
                }
            },
            Err(err) => eprintln!("irauthd: accept failed: {err}"),
        }
    }
    Ok(())
}

fn handle(mut stream: UnixStream, state: &State) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let cred = peer_cred(&stream)?;
    let mut line = String::new();
    BufReader::new(stream.try_clone()?)
        .take(MAX_REQUEST_BYTES)
        .read_line(&mut line)?;
    let response = if !line.ends_with('\n') {
        Response::Error(
            "protocol: request must be newline-terminated and at most 1024 bytes".into(),
        )
    } else {
        match decode_request(&line) {
            Ok(Request::Ping) => Response::Pong,
            Ok(Request::Status) => Response::Status(status(&state.backend)),
            Ok(Request::Authenticate { user, reason }) => {
                authenticate(cred.uid, &user, &reason, state)
            }
            Err(err) => Response::Error(format!("protocol: {err}")),
        }
    };
    stream.write_all(encode_response(&response).as_bytes())?;
    Ok(())
}

fn authenticate(peer_uid: u32, user: &str, reason: &str, state: &State) -> Response {
    let Some(target_uid) = uid_for_user(user) else {
        return Response::Error("unknown user".into());
    };
    if !may_authenticate(peer_uid, target_uid) {
        return Response::Error("peer may authenticate only itself".into());
    }
    if !rate_limit(peer_uid, &state.rate_limit) {
        return Response::Error("authentication request rate-limited".into());
    }
    let _camera = match state.camera_lock.lock() {
        Ok(lock) => lock,
        Err(_) => return Response::Error("authentication lock poisoned".into()),
    };

    // Enforce the hardware policy at the moment of authentication, not just at
    // installation. This prevents a later Howdy reconfiguration from silently
    // redirecting IRAuth to an ordinary RGB camera while an IR node still exists.
    let configured = match configured_camera() {
        Ok(Some(camera)) => camera,
        Ok(None) => return Response::Error("Howdy camera is not configured".into()),
        Err(err) => {
            eprintln!("irauthd: cannot read Howdy camera configuration: {err}");
            return Response::Error("Howdy camera configuration error".into());
        }
    };
    match irauth_hardware::strict_device_for_path(&configured.device_path) {
        Ok(Some(_)) => {}
        Ok(None) => {
            eprintln!(
                "irauthd: denied non-IR Howdy camera {}",
                configured.device_path.display()
            );
            return Response::Error("Howdy is not bound to a strict IR/depth camera".into());
        }
        Err(err) => {
            eprintln!("irauthd: camera policy check failed: {err}");
            return Response::Error("camera policy error".into());
        }
    }

    eprintln!(
        "irauthd: face verification requested user={user} reason={reason} camera={}",
        configured.device_path.display()
    );
    match state.backend.authenticate(user, reason) {
        Ok(result) if result.approved => {
            eprintln!("irauthd: APPROVED user={user}");
            Response::Ok("face verified".into())
        }
        Ok(result) => {
            eprintln!("irauthd: DENIED user={user}: {}", result.detail);
            Response::Error("face verification denied".into())
        }
        Err(err) => {
            eprintln!("irauthd: backend error user={user}: {err}");
            Response::Error("backend error".into())
        }
    }
}

fn status(backend: &Backend) -> DaemonStatus {
    let preflight = backend.preflight();
    let camera_strict = configured_camera()
        .ok()
        .flatten()
        .and_then(|c| {
            irauth_hardware::strict_device_for_path(&c.device_path)
                .ok()
                .flatten()
        })
        .is_some();
    DaemonStatus {
        backend: if preflight.howdy
            && preflight.pamtester
            && preflight.missing_models.is_empty()
            && camera_strict
        {
            "howdy-ready-ir-bound".into()
        } else {
            "howdy-incomplete".into()
        },
        strict_ir_devices: irauth_hardware::strict_devices()
            .map(|v| v.len())
            .unwrap_or(0),
        tpm_present: Path::new("/dev/tpmrm0").exists(),
    }
}

fn may_authenticate(peer_uid: u32, target_uid: u32) -> bool {
    peer_uid == 0 || peer_uid == target_uid
}

fn rate_limit(uid: u32, map: &Mutex<HashMap<u32, Instant>>) -> bool {
    let Ok(mut map) = map.lock() else {
        return false;
    };
    let now = Instant::now();
    if map
        .get(&uid)
        .is_some_and(|last| now.duration_since(*last) < MIN_REQUEST_INTERVAL)
    {
        return false;
    }
    map.insert(uid, now);
    true
}

fn peer_cred(stream: &UnixStream) -> io::Result<UCred> {
    let mut cred = UCred {
        _pid: 0,
        uid: u32::MAX,
        _gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<UCred>() as u32;
    let rc = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut cred as *mut UCred).cast::<c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred)
}

fn uid_for_user(user: &str) -> Option<u32> {
    fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut p = line.split(':');
            let name = p.next()?;
            let _pw = p.next()?;
            let uid = p.next()?;
            if name == user {
                uid.parse().ok()
            } else {
                None
            }
        })
}

fn gid_for_group(group: &str) -> Option<u32> {
    fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut p = line.split(':');
            let name = p.next()?;
            let _pw = p.next()?;
            let gid = p.next()?;
            if name == group {
                gid.parse().ok()
            } else {
                None
            }
        })
}

fn secure_socket(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    let gid = gid_for_group(SOCKET_GROUP).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("group {SOCKET_GROUP} does not exist"),
        )
    })?;
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
    let rc = unsafe { chown(cpath.as_ptr(), u32::MAX, gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_root_peer_cannot_request_authentication_for_another_user() {
        assert!(may_authenticate(1000, 1000));
        assert!(!may_authenticate(1000, 1001));
        assert!(may_authenticate(0, 1001));
    }

    #[test]
    fn rate_limit_is_per_peer_uid() {
        let map = Mutex::new(HashMap::new());
        assert!(rate_limit(1000, &map));
        assert!(!rate_limit(1000, &map));
        assert!(rate_limit(1001, &map));
    }
}
