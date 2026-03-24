//! File-backed `HostInterface` for development and testing.
//!
//! - Index: `{base_dir}/index.bin`
//! - Cache: `{base_dir}/cache/{hex_key}.bin`

use crate::host::HostInterface;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct FileHost {
    base_dir: PathBuf,
    index_writer: Option<fs::File>,
}

impl FileHost {
    pub fn new(base_dir: impl Into<PathBuf>) -> io::Result<Self> {
        let base_dir = base_dir.into();
        fs::create_dir_all(base_dir.join("cache"))?;
        Ok(FileHost { base_dir, index_writer: None })
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    fn index_path(&self) -> PathBuf {
        self.base_dir.join("index.bin")
    }

    fn index_tmp_path(&self) -> PathBuf {
        self.base_dir.join("index.bin.tmp")
    }

    fn cache_path(&self, key: &[u8; 16]) -> PathBuf {
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        self.base_dir.join("cache").join(format!("{}.bin", hex))
    }
}

impl HostInterface for FileHost {
    type Error = io::Error;

    // ── Index ───────────────────────────────────────────────────

    fn index_size(&mut self) -> Result<u64, Self::Error> {
        match fs::metadata(self.index_path()) {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn index_read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut file = match fs::File::open(self.index_path()) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        file.seek(SeekFrom::Start(offset))?;
        file.read(buf)
    }

    fn index_write_begin(&mut self) -> Result<(), Self::Error> {
        self.index_writer = Some(fs::File::create(self.index_tmp_path())?);
        Ok(())
    }

    fn index_write_append(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.index_writer
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "index_write_begin not called"))?
            .write_all(data)
    }

    fn index_write_commit(&mut self) -> Result<(), Self::Error> {
        if let Some(mut w) = self.index_writer.take() {
            w.flush()?;
        }
        fs::rename(self.index_tmp_path(), self.index_path())
    }

    // ── Data cache ──────────────────────────────────────────────

    fn cache_store(&mut self, key: &[u8; 16], data: &[u8]) -> Result<(), Self::Error> {
        let path = self.cache_path(key);
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, &path)
    }

    fn cache_read(&mut self, key: &[u8; 16], buf: &mut [u8]) -> Result<usize, Self::Error> {
        let path = self.cache_path(key);
        match fs::read(&path) {
            Ok(data) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e),
        }
    }

    // ── Utilities ───────────────────────────────────────────────

    fn now_millis(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    fn fill_random(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("getrandom failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        assert_eq!(host.index_size().unwrap(), 0);
    }

    #[test]
    fn index_write_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();

        host.index_write_begin().unwrap();
        host.index_write_append(b"hello").unwrap();
        host.index_write_append(b"world").unwrap();
        host.index_write_commit().unwrap();

        assert_eq!(host.index_size().unwrap(), 10);
        let mut buf = [0u8; 64];
        let n = host.index_read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"helloworld");
    }

    #[test]
    fn cache_store_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();

        let key = [0xAA; 16];
        host.cache_store(&key, b"encrypted data here").unwrap();

        let mut buf = [0u8; 256];
        let n = host.cache_read(&key, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"encrypted data here");
    }

    #[test]
    fn cache_miss() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();

        let key = [0xBB; 16];
        let mut buf = [0u8; 256];
        assert_eq!(host.cache_read(&key, &mut buf).unwrap(), 0);
    }

    #[test]
    fn cache_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();

        let key = [0xCC; 16];
        host.cache_store(&key, b"v1").unwrap();
        host.cache_store(&key, b"v2").unwrap();

        let mut buf = [0u8; 256];
        let n = host.cache_read(&key, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"v2");
    }
}
