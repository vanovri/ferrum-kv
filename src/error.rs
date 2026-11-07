use std::error::Error;
use std::fmt;
use std::io;
use std::net::AddrParseError;
use std::num::{ParseFloatError, ParseIntError};
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::time::SystemTimeError;

pub type EngineResult<T> = Result<T, EngineError>;

#[derive(Debug)]
pub enum EngineError {
    Io(io::Error),
    Protocol(String),
    WrongType { expected: &'static str, actual: &'static str },
    InvalidArgument(String),
    InvalidInt(ParseIntError),
    InvalidFloat(ParseFloatError),
    InvalidUtf8(Utf8Error),
    InvalidAddr(AddrParseError),
    SystemClock(SystemTimeError),
    LockPoisoned(&'static str),
    ChannelClosed(&'static str),
    CorruptedPersistence(String),
    ServerShutdown,
}

impl EngineError {
    pub fn to_resp_error_message(&self) -> String {
        match self {
            EngineError::WrongType { .. } => {
                "WRONGTYPE Operation against a key holding the wrong kind of value".to_string()
            }
            EngineError::Protocol(msg) => format!("ERR Protocol error: {}", msg),
            EngineError::InvalidArgument(msg) => format!("ERR {}", msg),
            EngineError::InvalidInt(_) => {
                "ERR value is not an integer or out of range".to_string()
            }
            EngineError::InvalidFloat(_) => "ERR value is not a valid float".to_string(),
            EngineError::InvalidUtf8(_) => "ERR invalid UTF-8 sequence".to_string(),
            EngineError::LockPoisoned(ctx) => format!("ERR internal lock poisoned ({})", ctx),
            EngineError::ChannelClosed(ctx) => format!("ERR subsystem channel closed ({})", ctx),
            EngineError::CorruptedPersistence(msg) => {
                format!("ERR persistence error: {}", msg)
            }
            EngineError::Io(err) => format!("ERR I/O failure: {}", err),
            EngineError::InvalidAddr(err) => format!("ERR invalid network address: {}", err),
            EngineError::SystemClock(err) => format!("ERR clock failure: {}", err),
            EngineError::ServerShutdown => "ERR server is shutting down".to_string(),
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Io(err) => write!(f, "I/O error: {}", err),
            EngineError::Protocol(msg) => write!(f, "RESP3 protocol error: {}", msg),
            EngineError::WrongType { expected, actual } => {
                write!(f, "WRONGTYPE expected {}, found {}", expected, actual)
            }
            EngineError::InvalidArgument(msg) => write!(f, "invalid argument: {}", msg),
            EngineError::InvalidInt(err) => write!(f, "integer parse error: {}", err),
            EngineError::InvalidFloat(err) => write!(f, "float parse error: {}", err),
            EngineError::InvalidUtf8(err) => write!(f, "UTF-8 decode error: {}", err),
            EngineError::InvalidAddr(err) => write!(f, "address parse error: {}", err),
            EngineError::SystemClock(err) => write!(f, "system clock error: {}", err),
            EngineError::LockPoisoned(ctx) => write!(f, "concurrency lock poisoned in {}", ctx),
            EngineError::ChannelClosed(ctx) => write!(f, "MPSC channel closed in {}", ctx),
            EngineError::CorruptedPersistence(msg) => write!(f, "corrupted persistence: {}", msg),
            EngineError::ServerShutdown => write!(f, "engine shutdown in progress"),
        }
    }
}

impl Error for EngineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EngineError::Io(err) => Some(err),
            EngineError::InvalidInt(err) => Some(err),
            EngineError::InvalidFloat(err) => Some(err),
            EngineError::InvalidUtf8(err) => Some(err),
            EngineError::InvalidAddr(err) => Some(err),
            EngineError::SystemClock(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for EngineError {
    fn from(err: io::Error) -> Self {
        EngineError::Io(err)
    }
}

impl From<ParseIntError> for EngineError {
    fn from(err: ParseIntError) -> Self {
        EngineError::InvalidInt(err)
    }
}

impl From<ParseFloatError> for EngineError {
    fn from(err: ParseFloatError) -> Self {
        EngineError::InvalidFloat(err)
    }
}

impl From<Utf8Error> for EngineError {
    fn from(err: Utf8Error) -> Self {
        EngineError::InvalidUtf8(err)
    }
}

impl From<FromUtf8Error> for EngineError {
    fn from(err: FromUtf8Error) -> Self {
        EngineError::InvalidUtf8(err.utf8_error())
    }
}

impl From<AddrParseError> for EngineError {
    fn from(err: AddrParseError) -> Self {
        EngineError::InvalidAddr(err)
    }
}

impl From<SystemTimeError> for EngineError {
    fn from(err: SystemTimeError) -> Self {
        EngineError::SystemClock(err)
    }
}
