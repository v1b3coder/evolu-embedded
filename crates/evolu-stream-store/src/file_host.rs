//! File-backed `HostStore` for development and testing.
//!
//! - Index: `{base_dir}/index.bin`
//! - Blobs: `{base_dir}/blobs/{hex_ts}.bin`

use crate::host::HostStore;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub struct FileHost {
    base_dir: PathBuf,
    index_writer: Option<fs::File>,
}

impl FileHost {
    pub fn new(base_dir: impl Into<PathBuf>) -> io::Result<Self> {
        let base_dir = base_dir.into();
        fs::create_dir_all(base_dir.join("blobs"))?;
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

    fn blob_path(&self, ts: &[u8; 16]) -> PathBuf {
        let hex: String = ts.iter().map(|b| format!("{:02x}", b)).collect();
        self.base_dir.join("blobs").join(format!("{}.bin", hex))
    }
}

impl HostStore for FileHost {
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
            w.sync_data()?;
        }
        fs::rename(self.index_tmp_path(), self.index_path())
    }

    // ── Blob cache ──────────────────────────────────────────────

    fn put_blob(&mut self, ts: &[u8; 16], data: &[u8]) -> Result<(), Self::Error> {
        let path = self.blob_path(ts);
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, &path)
    }

    fn get_blob(&mut self, ts: &[u8; 16], buf: &mut [u8]) -> Result<usize, Self::Error> {
        let path = self.blob_path(ts);
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
    fn blob_put_get() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();

        let ts = [0xAA; 16];
        host.put_blob(&ts, b"encrypted data here").unwrap();

        let mut buf = [0u8; 256];
        let n = host.get_blob(&ts, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"encrypted data here");
    }

    #[test]
    fn blob_miss() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();

        let mut buf = [0u8; 256];
        assert_eq!(host.get_blob(&[0xBB; 16], &mut buf).unwrap(), 0);
    }

    #[test]
    fn blob_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();

        let ts = [0xCC; 16];
        host.put_blob(&ts, b"v1").unwrap();
        host.put_blob(&ts, b"v2").unwrap();

        let mut buf = [0u8; 256];
        let n = host.get_blob(&ts, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"v2");
    }
}
