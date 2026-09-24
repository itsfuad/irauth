use irauth_core::{encode_request, Request, SOCKET_PATH};
use std::ffi::CStr;
use std::io::{BufRead, BufReader, Write};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

const PAM_SUCCESS: c_int = 0;
const PAM_SERVICE_ERR: c_int = 3;
const PAM_SYSTEM_ERR: c_int = 4;
const PAM_AUTH_ERR: c_int = 7;

#[link(name = "pam")]
extern "C" {
    fn pam_get_user(pamh: *mut c_void, user: *mut *const c_char, prompt: *const c_char) -> c_int;
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| authenticate_inner(pamh, argc, argv))).unwrap_or(PAM_SYSTEM_ERR)
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

fn authenticate_inner(pamh: *mut c_void, argc: c_int, argv: *const *const c_char) -> c_int {
    if pamh.is_null() { return PAM_SERVICE_ERR; }
    let mut user_ptr: *const c_char = std::ptr::null();
    let rc = unsafe { pam_get_user(pamh, &mut user_ptr, std::ptr::null()) };
    if rc != PAM_SUCCESS || user_ptr.is_null() { return PAM_AUTH_ERR; }
    let Ok(user) = unsafe { CStr::from_ptr(user_ptr) }.to_str() else { return PAM_AUTH_ERR };
    let reason = parse_reason(argc, argv).unwrap_or_else(|| "pam".to_owned());
    match request_auth(user, &reason) {
        Ok(true) => PAM_SUCCESS,
        Ok(false) => PAM_AUTH_ERR,
        Err(_) => PAM_AUTH_ERR,
    }
}

fn request_auth(user: &str, reason: &str) -> std::io::Result<bool> {
    let mut stream = UnixStream::connect(SOCKET_PATH)?;
    stream.set_read_timeout(Some(Duration::from_secs(35)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(encode_request(&Request::Authenticate {
        user: user.to_owned(), reason: reason.to_owned(),
    }).as_bytes())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(line.starts_with("OK\t"))
}

fn parse_reason(argc: c_int, argv: *const *const c_char) -> Option<String> {
    if argc <= 0 || argv.is_null() { return None; }
    for i in 0..argc {
        let ptr = unsafe { *argv.add(i as usize) };
        if ptr.is_null() { continue; }
        let Ok(arg) = unsafe { CStr::from_ptr(ptr) }.to_str() else { continue };
        if let Some(reason) = arg.strip_prefix("reason=") {
            if !reason.is_empty() && reason.len() <= 128 {
                return Some(reason.to_owned());
            }
        }
    }
    None
}
