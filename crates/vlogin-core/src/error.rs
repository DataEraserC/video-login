//! Error type shared across the core. `Channel` errors carry the structured
//! "reserved but not implemented" contract hosts render as-is; everything
//! else is a plain message.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// A channel/method contract problem: unknown channel, reserved method,
    /// bad parameters. Hosts surface these verbatim.
    Channel(String),
    /// Cookie codec/storage problem.
    Cookie(String),
    /// Transport or upstream API problem.
    Http(String),
    /// Anything else.
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn channel(message: impl Into<String>) -> Self {
        Error::Channel(message.into())
    }
    pub fn cookie(message: impl Into<String>) -> Self {
        Error::Cookie(message.into())
    }
    pub fn http(message: impl Into<String>) -> Self {
        Error::Http(message.into())
    }
    pub fn other(message: impl Into<String>) -> Self {
        Error::Other(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Json(e) => write!(f, "{e}"),
            Error::Channel(m) | Error::Cookie(m) | Error::Http(m) | Error::Other(m) => {
                write!(f, "{m}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}
