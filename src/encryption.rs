use anyhow::anyhow;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::stream::{DecryptorBE32, EncryptorBE32},
};
use std::io::{Read, Write};

pub fn write_encrypted(
    mut to: impl Write,
    cipher: &mut EncryptorBE32<XChaCha20Poly1305>,
    buf: &[u8],
) -> anyhow::Result<()> {
    let ciphertext = cipher.encrypt_next(buf)?;

    to.write_all(&ciphertext)?;

    Ok(())
}

pub fn read_decrypted(
    mut from: impl Read,
    cipher: &mut DecryptorBE32<XChaCha20Poly1305>,
    buf: &mut [u8],
) -> anyhow::Result<()> {
    let mut ciphertext = vec![0u8; buf.len() + 16];

    from.read_exact(&mut ciphertext)?;

    let plaintext = cipher.decrypt_next(ciphertext.as_slice())?;

    buf.clone_from_slice(&plaintext);

    Ok(())
}

pub fn encrypt(
    mut src: impl Read,
    mut dst: impl Write,
    mut cipher: EncryptorBE32<XChaCha20Poly1305>,
) -> Result<(), anyhow::Error> {
    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = src.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = cipher
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dst.write_all(&ciphertext)?;
        } else {
            let ciphertext = cipher
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dst.write_all(&ciphertext)?;
            break;
        }
    }

    Ok(())
}

pub fn decrypt(
    mut src: impl Read,
    mut dst: impl Write,
    mut cipher: DecryptorBE32<XChaCha20Poly1305>,
) -> Result<(), anyhow::Error> {
    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = src.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = cipher
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting: {}", err))?;
            dst.write_all(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = cipher
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting: {}", err))?;
            dst.write_all(&plaintext)?;
            break;
        }
    }

    Ok(())
}
