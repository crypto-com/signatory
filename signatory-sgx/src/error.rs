#[cfg(feature = "std")]
use crossbeam_channel::{RecvError, SendError};
use std::error::Error as StdError;
use std::{self, fmt};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Error {
    pub what: String,
    pub kind: ErrorKind,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ErrorKind {
    Common,
    Stop,
}

impl Error {
    pub fn new<T: Into<String>>(e: T) -> Self {
        Self {
            what: e.into(),
            kind: ErrorKind::Common,
        }
    }

    pub fn stop() -> Self {
        Self {
            what: "".into(),
            kind: ErrorKind::Stop,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.what)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        &self.what
    }
}

impl From<std::io::Error> for Error {
    fn from(s: std::io::Error) -> Error {
        Error {
            what: s.description().into(),
            kind: ErrorKind::Common,
        }
    }
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Error {
        Error {
            what: s.into(),
            kind: ErrorKind::Common,
        }
    }
}

impl From<String> for Error {
    fn from(s: String) -> Error {
        Error {
            what: s,
            kind: ErrorKind::Common,
        }
    }
}

#[cfg(feature = "std")]
impl From<SendError<Vec<u8>>> for Error {
    fn from(_s: SendError<Vec<u8>>) -> Error {
        Error {
            what: "send data to channel error".into(),
            kind: ErrorKind::Common,
        }
    }
}

#[cfg(feature = "std")]
impl From<RecvError> for Error {
    fn from(_s: RecvError) -> Error {
        Error {
            what: "receive data from channel error, the enclave service may stopped".into(),
            kind: ErrorKind::Common,
        }
    }
}
