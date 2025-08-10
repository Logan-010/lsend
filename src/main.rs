use blake3::{Hash, Hasher};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{
        KeyInit, OsRng,
        rand_core::RngCore,
        stream::{DecryptorBE32, EncryptorBE32},
    },
};
use clap::Parser;
use cli::{Cli, Mode};
use encryption::{decrypt, encrypt, read_decrypted, write_encrypted};
use flate2::{Compression, read, write};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
};
use x25519_dalek::{EphemeralSecret, PublicKey};

mod cli;
mod encryption;

const SERVICE_TYPE: &str = "_netfs._tcp.local.";
const KEY_CONTEXT: &str = "lsend key generation for XChaCha20 cipher";

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Share => {
            let mdns = ServiceDaemon::new()?;

            let recv = mdns.browse(SERVICE_TYPE)?;

            let id = format!(
                "{}.{}",
                cli.id.expect("id not provided in share mode"),
                SERVICE_TYPE
            );

            println!("searching for clients...");

            let mut address = None;
            while let Ok(event) = recv.recv() {
                if let ServiceEvent::ServiceResolved(info) = event {
                    let resolved = info.as_resolved_service();

                    if resolved.fullname == id {
                        println!("client found");

                        let ip_base = resolved.host.trim_end_matches(".local.");

                        let ip = format!("{}:{}", ip_base, resolved.port);

                        println!("found client address: {ip}");

                        address = Some(ip);

                        break;
                    }
                }
            }

            let mut stream = TcpStream::connect(address.unwrap())?;

            println!("connected to client");

            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            stream.write_all(&salt)?;

            let mut nonce = [0u8; 19];
            OsRng.fill_bytes(&mut nonce);
            stream.write_all(&nonce)?;

            let key = EphemeralSecret::random();
            stream.write_all(PublicKey::from(&key).as_bytes())?;

            let mut public_key_bytes = [0u8; 32];
            stream.read_exact(&mut public_key_bytes)?;
            let public_key = PublicKey::from(public_key_bytes);

            let shared_key = key.diffie_hellman(&public_key);

            let key = Hasher::new_derive_key(KEY_CONTEXT)
                .update(&salt)
                .update(shared_key.as_bytes())
                .finalize();

            let mut cipher = EncryptorBE32::from_aead(
                XChaCha20Poly1305::new(key.as_bytes().into()),
                &nonce.into(),
            );

            let name = cli.path.display().to_string();

            write_encrypted(&mut stream, &mut cipher, &(name.len() as u64).to_le_bytes())?;

            write_encrypted(&mut stream, &mut cipher, name.as_bytes())?;

            let size = fs::metadata(&cli.path)?.len();
            write_encrypted(&mut stream, &mut cipher, &size.to_le_bytes())?;

            let hash = Hasher::new().update_mmap_rayon(&cli.path)?.finalize();
            write_encrypted(&mut stream, &mut cipher, hash.as_bytes())?;

            let file = File::open(&cli.path)?;

            println!("sending file");

            encrypt(
                read::GzEncoder::new(file, Compression::new(cli.level)),
                stream,
                cipher,
            )?;

            println!("sent");

            mdns.shutdown()?;
        }
        Mode::Save => {
            fs::create_dir_all(&cli.path)?;

            let mdns = ServiceDaemon::new()?;

            let ip = local_ip_address::local_ip()?;

            let mut name_bytes = [0u8; 3];
            OsRng.fill_bytes(&mut name_bytes);
            let name = hex::encode(name_bytes);

            println!("id: {name}");

            let listener = TcpListener::bind(SocketAddr::from((ip, cli.port)))?;

            let service = ServiceInfo::new(
                SERVICE_TYPE,
                &name,
                &format!("{ip}.local."),
                ip,
                listener.local_addr()?.port(),
                HashMap::new(),
            )?;

            mdns.register(service)?;

            while let Ok((mut stream, address)) = listener.accept() {
                let mut salt = [0u8; 16];
                if let Err(e) = stream.read_exact(&mut salt) {
                    eprintln!("failed to read salt: {e}");
                    continue;
                }

                let mut nonce = [0u8; 19];
                if let Err(e) = stream.read_exact(&mut nonce) {
                    eprintln!("failed to read nonce: {e}");
                    continue;
                }

                let mut public_key_bytes = [0u8; 32];
                if let Err(e) = stream.read_exact(&mut public_key_bytes) {
                    eprintln!("failed to read public key: {e}");
                    continue;
                }
                let public_key = PublicKey::from(public_key_bytes);

                let key = EphemeralSecret::random();
                if let Err(e) = stream.write_all(PublicKey::from(&key).as_bytes()) {
                    eprintln!("failed to write public key to stream: {e}");
                    continue;
                }

                let shared_key = key.diffie_hellman(&public_key);

                let key = Hasher::new_derive_key(KEY_CONTEXT)
                    .update(&salt)
                    .update(shared_key.as_bytes())
                    .finalize();

                let mut cipher = DecryptorBE32::from_aead(
                    XChaCha20Poly1305::new(key.as_bytes().into()),
                    &nonce.into(),
                );

                let mut name_length_bytes = [0u8; 8];

                if let Err(e) = read_decrypted(&mut stream, &mut cipher, &mut name_length_bytes) {
                    eprintln!("failed to read name length from stream: {e}");
                    continue;
                }

                let name_length: u64 = u64::from_le_bytes(name_length_bytes);

                let mut name_bytes = vec![0u8; name_length as usize];

                if let Err(e) = read_decrypted(&mut stream, &mut cipher, &mut name_bytes) {
                    eprintln!("failed to read name from stream: {e}");
                    continue;
                }

                let Ok(name) = String::from_utf8(name_bytes) else {
                    eprintln!("fame not valid utf8");
                    continue;
                };

                let mut size_bytes = [0u8; 8];

                if let Err(e) = read_decrypted(&mut stream, &mut cipher, &mut size_bytes) {
                    eprintln!("failed to read size from stream: {e}");
                    continue;
                }

                let size = u64::from_le_bytes(size_bytes);

                let mut hash_bytes = [0u8; 32];

                if let Err(e) = read_decrypted(&mut stream, &mut cipher, &mut hash_bytes) {
                    eprintln!("failed to read hash from stream: {e}");
                    continue;
                }

                let hash = Hash::from_bytes(hash_bytes);

                println!(
                    "incoming file, accept? (y/n)\nname: {name}\nsize: {size}\nfrom: {address}\nhash: {hash}"
                );

                let mut rejected = false;

                loop {
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;

                    if input.trim().to_lowercase() == "y" {
                        println!("file accepted...");
                        break;
                    } else if input.trim().to_lowercase() == "n" {
                        println!("file rejected");
                        rejected = true;
                        break;
                    } else {
                        println!("Please enter y or n...");
                    }
                }

                if rejected {
                    continue;
                }

                let path = cli.path.join(&name);

                let file = match File::create_new(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("failed to create file: {e}");
                        continue;
                    }
                };

                println!("transfering file...");

                if let Err(e) = decrypt(&mut stream, write::GzDecoder::new(file), cipher) {
                    eprintln!("failed to copy from stream to file: {e}");
                    continue;
                };

                let out_hash = Hasher::new().update_mmap_rayon(&path)?.finalize();

                println!("saved to {name}");

                if out_hash != hash {
                    eprintln!("file transfered, yet hashes do not match");
                } else {
                    println!("hashes match");
                }
            }

            mdns.shutdown()?;
        }
    }

    Ok(())
}
