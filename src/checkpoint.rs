//! Minimal checkpoint/resume scaffolding.
//!
//! Writes a plain-text checkpoint file before search begins and removes it on
//! completion.  The file contains enough metadata to reconstruct the search
//! parameters if the process is restarted, but full resume logic is not yet
//! implemented.

use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

/// A lightweight snapshot of search parameters.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Algorithm that was (or will be) executed.
    pub algorithm: String,
    /// Lower bound of the search range.
    pub start: i128,
    /// Step size.
    pub step: i128,
    /// Total candidate count.
    pub total: u128,
    /// Hex-encoded `r` scalar.
    pub r_hex: String,
    /// Hex-encoded `s` scalar.
    pub s_hex: String,
    /// Hex-encoded `z` scalar.
    pub z_hex: String,
    /// Hex-encoded target public key.
    pub pubkey_hex: String,
    /// If present, the last index that was evaluated before interruption.
    pub last_index: Option<u128>,
}

impl Checkpoint {
    /// Serialize the checkpoint to a writer in key=value format.
    pub fn write_to(&self, writer: &mut dyn Write) -> io::Result<()> {
        writeln!(writer, "algorithm={}", self.algorithm)?;
        writeln!(writer, "start={}", self.start)?;
        writeln!(writer, "step={}", self.step)?;
        writeln!(writer, "total={}", self.total)?;
        writeln!(writer, "r={}", self.r_hex)?;
        writeln!(writer, "s={}", self.s_hex)?;
        writeln!(writer, "z={}", self.z_hex)?;
        writeln!(writer, "pubkey={}", self.pubkey_hex)?;
        if let Some(idx) = self.last_index {
            writeln!(writer, "last_index={}", idx)?;
        }
        Ok(())
    }
}

/// Write a checkpoint file to `dir`.  Returns the path of the written file.
pub fn write(dir: &Path, checkpoint: &Checkpoint) -> io::Result<PathBuf> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    let path = dir.join(format!(
        "checkpoint_{}_{}.txt",
        checkpoint.algorithm,
        std::process::id()
    ));
    let mut file = File::create(&path)?;
    checkpoint.write_to(&mut file)?;
    file.flush()?;
    Ok(path)
}

/// Remove the checkpoint file at `path` if it exists.
///
/// Returns an error if the file exists but could not be removed.
pub fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_text_format() {
        let cp = Checkpoint {
            algorithm: "bsgs".into(),
            start: -100,
            step: 3,
            total: 1_000_000,
            r_hex: "0x01".into(),
            s_hex: "0x02".into(),
            z_hex: "0x03".into(),
            pubkey_hex: "0x04".into(),
            last_index: Some(42_000),
        };

        let mut buf = Vec::new();
        cp.write_to(&mut buf).unwrap();
        let body = String::from_utf8(buf).unwrap();
        assert!(body.contains("algorithm=bsgs"));
        assert!(body.contains("start=-100"));
        assert!(body.contains("last_index=42000"));
    }

    #[test]
    fn remove_nonexistent_is_ok() {
        let tmp = std::env::temp_dir().join("nonce_cracker_test_remove_nonexistent");
        assert!(super::remove(&tmp).is_ok());
    }
}
