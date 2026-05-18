//! Minimal checkpoint/resume scaffolding.
//!
//! Writes a plain-text checkpoint file before search begins and removes it on
//! completion.  The file contains enough metadata to reconstruct the search
//! parameters if the process is restarted, but full resume logic is not yet
//! implemented.

use std::{
    fs::{self, File},
    io::{self, BufRead, Write},
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
    pub fn write_to(&self,
        writer: &mut dyn Write,
    ) -> io::Result<()> {
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

    /// Deserialize a checkpoint from a reader.
    ///
    /// Returns an error if any required field is missing, a line is malformed,
    /// or an unknown key is encountered.
    pub fn read_from(reader: &mut dyn BufRead) -> io::Result<Self> {
        let mut algorithm: Option<String> = None;
        let mut start: Option<i128> = None;
        let mut step: Option<i128> = None;
        let mut total: Option<u128> = None;
        let mut r_hex: Option<String> = None;
        let mut s_hex: Option<String> = None;
        let mut z_hex: Option<String> = None;
        let mut pubkey_hex: Option<String> = None;
        let mut last_index: Option<u128> = None;

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("malformed checkpoint line (missing '='): {line}")
                ));
            };
            match key {
                "algorithm" => algorithm = Some(value.to_string()),
                "start" => start = Some(value.parse().map_err(|e| io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid start: {e}")
                ))?),
                "step" => step = Some(value.parse().map_err(|e| io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid step: {e}")
                ))?),
                "total" => total = Some(value.parse().map_err(|e| io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid total: {e}")
                ))?),
                "r" => r_hex = Some(value.to_string()),
                "s" => s_hex = Some(value.to_string()),
                "z" => z_hex = Some(value.to_string()),
                "pubkey" => pubkey_hex = Some(value.to_string()),
                "last_index" => last_index = Some(value.parse().map_err(|e| io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid last_index: {e}")
                ))?),
                other => return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown checkpoint key: {other}")
                )),
            }
        }

        macro_rules! required {
            ($field:expr, $name:literal) => {
                $field.ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("missing required checkpoint field: {}", $name)
                ))?
            };
        }

        Ok(Checkpoint {
            algorithm: required!(algorithm, "algorithm"),
            start: required!(start, "start"),
            step: required!(step, "step"),
            total: required!(total, "total"),
            r_hex: required!(r_hex, "r"),
            s_hex: required!(s_hex, "s"),
            z_hex: required!(z_hex, "z"),
            pubkey_hex: required!(pubkey_hex, "pubkey"),
            last_index,
        })
    }

    /// Return the default file name for this checkpoint.
    pub fn file_name(&self) -> String {
        format!(
            "checkpoint_{}_{}.txt",
            self.algorithm,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        )
    }
}

/// Write a checkpoint file to `dir`.  Returns the path of the written file.
pub fn write(dir: &Path, checkpoint: &Checkpoint) -> io::Result<PathBuf> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    let path = dir.join(checkpoint.file_name());
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
        let mut reader = io::BufReader::new(&buf[..]);
        let parsed = Checkpoint::read_from(&mut reader).unwrap();

        assert_eq!(parsed.algorithm, cp.algorithm);
        assert_eq!(parsed.start, cp.start);
        assert_eq!(parsed.step, cp.step);
        assert_eq!(parsed.total, cp.total);
        assert_eq!(parsed.r_hex, cp.r_hex);
        assert_eq!(parsed.s_hex, cp.s_hex);
        assert_eq!(parsed.z_hex, cp.z_hex);
        assert_eq!(parsed.pubkey_hex, cp.pubkey_hex);
        assert_eq!(parsed.last_index, cp.last_index);
    }

    #[test]
    fn read_rejects_missing_field() {
        let data = b"algorithm=scan\nstart=0\nstep=1\n";
        let mut reader = io::BufReader::new(&data[..]);
        let err = Checkpoint::read_from(&mut reader).unwrap_err();
        assert!(err.to_string().contains("missing required"));
    }

    #[test]
    fn read_rejects_malformed_line() {
        let data = b"algorithm=scan\nstart=0\nstep=1\ntotal=10\nr=0x01\ns=0x02\nz=0x03\npubkey=0x04\nbadline\n";
        let mut reader = io::BufReader::new(&data[..]);
        let err = Checkpoint::read_from(&mut reader).unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }

    #[test]
    fn read_rejects_unknown_key() {
        let data = b"algorithm=scan\nstart=0\nstep=1\ntotal=10\nr=0x01\ns=0x02\nz=0x03\npubkey=0x04\nunknown_key=val\n";
        let mut reader = io::BufReader::new(&data[..]);
        let err = Checkpoint::read_from(&mut reader).unwrap_err();
        assert!(err.to_string().contains("unknown checkpoint key"));
    }

    #[test]
    fn remove_nonexistent_is_ok() {
        let tmp = std::env::temp_dir().join("nonce_cracker_test_remove_nonexistent");
        assert!(super::remove(&tmp).is_ok());
    }
}
