use chacha20::{
    XChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use rand::RngCore;
use std::io::{Read, Write};

pub struct EncryptionReader<R: Read> {
    cipher: XChaCha20,
    inner: R,
    buffer: [u8; 2048],
}

impl<R: Read> EncryptionReader<R> {
    pub fn new(mut inner: R, key: &[u8; 32]) -> std::io::Result<Self> {
        let mut iv = [0u8; 24];
        inner.read_exact(&mut iv)?;
        let cipher = XChaCha20::new(key.into(), &iv.into());
        Ok(Self {
            cipher,
            inner,
            buffer: [0u8; 2048],
        })
    }
}

impl<R: Read> Read for EncryptionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(&mut self.buffer)?;
        if read == 0 {
            return Ok(0);
        }

        self.cipher.apply_keystream(&mut self.buffer[..read]);

        let copy_len = buf.len().min(read);
        buf[..copy_len].copy_from_slice(&self.buffer[..copy_len]);
        Ok(copy_len)
    }
}

pub struct EncryptionWriter<W: Write> {
    cipher: XChaCha20,
    inner: W,
    iv_written: bool,
    iv: [u8; 24],
}

impl<W: Write> EncryptionWriter<W> {
    pub fn new(inner: W, key: &[u8; 32]) -> std::io::Result<Self> {
        let mut iv = [0u8; 24];
        rand::rng().fill_bytes(&mut iv);
        let cipher = XChaCha20::new(key.into(), &iv.into());

        Ok(Self {
            cipher,
            inner,
            iv_written: false,
            iv,
        })
    }
}

impl<W: Write> Write for EncryptionWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.iv_written {
            self.inner.write_all(&self.iv)?;
            self.iv_written = true;
        }

        let mut encrypted = buf.to_vec();
        self.cipher.apply_keystream(&mut encrypted);
        self.inner.write_all(&encrypted)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
