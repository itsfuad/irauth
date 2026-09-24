use std::fmt;

pub const SOCKET_PATH: &str = "/run/irauth/irauthd.sock";
pub const SOCKET_GROUP: &str = "irauth";
pub const HOWDY_PAM_SERVICE: &str = "irauth-howdy";
pub const PASSKEY_PAM_SERVICE: &str = "irauth-passkey";
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Authenticate { user: String, reason: String },
    Status,
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Ok(String),
    Error(String),
    Status(DaemonStatus),
    Pong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStatus {
    pub backend: String,
    pub strict_ir_devices: usize,
    pub tpm_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Empty,
    InvalidCommand,
    InvalidField,
    UnsupportedVersion,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Empty => "empty request",
            Self::InvalidCommand => "invalid command",
            Self::InvalidField => "invalid field",
            Self::UnsupportedVersion => "unsupported protocol version",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ProtocolError {}

fn valid_field(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.bytes().any(|b| matches!(b, b'\n' | b'\r' | b'\t' | 0))
}

pub fn encode_request(req: &Request) -> String {
    match req {
        Request::Authenticate { user, reason } => {
            format!("V{}\tAUTH\t{}\t{}\n", PROTOCOL_VERSION, user, reason)
        }
        Request::Status => format!("V{}\tSTATUS\n", PROTOCOL_VERSION),
        Request::Ping => format!("V{}\tPING\n", PROTOCOL_VERSION),
    }
}

pub fn decode_request(line: &str) -> Result<Request, ProtocolError> {
    let line = line.trim_end_matches(|c| c == '\r' || c == '\n');
    if line.is_empty() {
        return Err(ProtocolError::Empty);
    }
    let mut parts = line.split('\t');
    let version = parts.next().ok_or(ProtocolError::Empty)?;
    let parsed_version = version
        .strip_prefix('V')
        .and_then(|v| v.parse::<u32>().ok())
        .ok_or(ProtocolError::UnsupportedVersion)?;
    if parsed_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    match parts.next() {
        Some("AUTH") => {
            let user = parts.next().ok_or(ProtocolError::InvalidField)?;
            let reason = parts.next().ok_or(ProtocolError::InvalidField)?;
            if parts.next().is_some() || !valid_field(user) || !valid_field(reason) {
                return Err(ProtocolError::InvalidField);
            }
            Ok(Request::Authenticate {
                user: user.to_owned(),
                reason: reason.to_owned(),
            })
        }
        Some("STATUS") if parts.next().is_none() => Ok(Request::Status),
        Some("PING") if parts.next().is_none() => Ok(Request::Ping),
        _ => Err(ProtocolError::InvalidCommand),
    }
}

pub fn encode_response(resp: &Response) -> String {
    match resp {
        Response::Ok(msg) => format!("OK\t{}\n", sanitize(msg)),
        Response::Error(msg) => format!("ERR\t{}\n", sanitize(msg)),
        Response::Pong => "PONG\n".to_owned(),
        Response::Status(status) => format!(
            "STATUS\tbackend={}\tir={}\ttpm={}\n",
            sanitize(&status.backend),
            status.strict_ir_devices,
            if status.tpm_present { 1 } else { 0 }
        ),
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if matches!(c, '\n' | '\r' | '\t' | '\0') { ' ' } else { c })
        .take(256)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_round_trip() {
        let req = Request::Authenticate {
            user: "alice".into(),
            reason: "sudo".into(),
        };
        assert_eq!(decode_request(&encode_request(&req)).unwrap(), req);
    }

    #[test]
    fn rejects_control_characters() {
        assert_eq!(
            decode_request("V1\tAUTH\talice\tbad\textra\n"),
            Err(ProtocolError::InvalidField)
        );
    }

    #[test]
    fn rejects_old_protocol() {
        assert_eq!(
            decode_request("V0\tPING\n"),
            Err(ProtocolError::UnsupportedVersion)
        );
    }
}
