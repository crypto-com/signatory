use std::{self, fmt};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Error(String);

impl Error {
    /// Error description
    /// This function returns an actual error str when running in `std` environment
    pub fn what(&self) -> &str {
        &self.0
    }

    pub fn new<T: Into<String>>(e: T) -> Self {
        Self(e.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        &self.0
    }
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Error {
        Error(s.into())
    }
}
