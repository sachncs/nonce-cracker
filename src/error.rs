#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Self(format!("hex parse error: {e}"))
    }
}
impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Self(format!("number parse error: {e}"))
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self(format!("io error: {e}"))
    }
}
impl From<crate::logging::LoggingError> for Error {
    fn from(e: crate::logging::LoggingError) -> Self {
        Self(format!("logging error: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
