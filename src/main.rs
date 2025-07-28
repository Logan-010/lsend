use blake3::{Hash, Hasher};
use clap::Parser;
use cli::{Cli, Mode};
use encryption::{EncryptionReader, EncryptionWriter};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
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

                        println!("found client address: {}", ip);

                        address = Some(ip);

                        break;
                    }
                }
            }

            let mut stream = TcpStream::connect(address.unwrap())?;

            println!("connected to client");

            let key = EphemeralSecret::random();

            stream.write_all(PublicKey::from(&key).as_bytes())?;

            let mut public_key_bytes = [0u8; 32];

            stream.read_exact(&mut public_key_bytes)?;

            let public_key = PublicKey::from(public_key_bytes);

            let shared_key = key.diffie_hellman(&public_key);

            let encrypted = EncryptionWriter::new(stream, shared_key.as_bytes())?;
            let mut compressed = GzEncoder::new(encrypted, Compression::new(cli.level));

            let name = cli.path.display().to_string();

            compressed.write_all(&(name.len() as u64).to_le_bytes())?;

            compressed.flush()?;

            compressed.write_all(name.as_bytes())?;

            compressed.flush()?;

            let size = fs::metadata(&cli.path)?.len();

            compressed.write_all(&size.to_le_bytes())?;

            compressed.flush()?;

            let mut hasher = Hasher::new();

            hasher.update_mmap_rayon(&cli.path)?;

            let hash = hasher.finalize();

            compressed.write_all(hash.as_bytes())?;

            compressed.flush()?;

            let mut file = File::open(&cli.path)?;

            println!("sending file");

            io::copy(&mut file, &mut compressed)?;

            compressed.flush()?;

            println!("sent");

            mdns.shutdown()?;
        }
        Mode::Save => {
            fs::create_dir_all(&cli.path)?;

            let mdns = ServiceDaemon::new()?;

            let ip = local_ip_address::local_ip()?;

            let name = hex::encode(rand::random::<[u8; 3]>());

            println!("id: {}", name);

            let listener = TcpListener::bind(SocketAddr::from((ip, cli.port)))?;

            let service = ServiceInfo::new(
                SERVICE_TYPE,
                &name,
                &format!("{}.local.", ip),
                ip,
                listener.local_addr()?.port(),
                HashMap::new(),
            )?;

            mdns.register(service)?;

            while let Ok((mut stream, address)) = listener.accept() {
                let key = EphemeralSecret::random();

                if let Err(e) = stream.write_all(PublicKey::from(&key).as_bytes()) {
                    eprintln!("failed to write public key to stream: {}", e);
                    continue;
                }

                stream.flush()?;

                let mut public_key_bytes = [0u8; 32];

                if let Err(e) = stream.read_exact(&mut public_key_bytes) {
                    eprintln!("failed to read public key from stream: {}", e);
                    continue;
                }

                let public_key = PublicKey::from(public_key_bytes);

                let shared_key = key.diffie_hellman(&public_key);

                let decrypted = EncryptionReader::new(stream, shared_key.as_bytes())?;
                let mut decompressed = GzDecoder::new(decrypted);

                let mut name_length_bytes = [0u8; 8];

                if let Err(e) = decompressed.read_exact(&mut name_length_bytes) {
                    eprintln!("failed to read name length from stream: {}", e);
                    continue;
                }

                let name_length: u64 = u64::from_le_bytes(name_length_bytes);

                let mut name_bytes = vec![0u8; name_length as usize];

                if let Err(e) = decompressed.read_exact(&mut name_bytes) {
                    eprintln!("failed to read name from stream: {}", e);
                    continue;
                }

                let Ok(name) = String::from_utf8(name_bytes) else {
                    eprintln!("fame not valid utf8");
                    continue;
                };

                let mut size_bytes = [0u8; 8];

                if let Err(e) = decompressed.read_exact(&mut size_bytes) {
                    eprintln!("failed to read size from stream: {}", e);
                    continue;
                }

                let size = u64::from_le_bytes(size_bytes);

                let mut hash_bytes = [0u8; 32];

                if let Err(e) = decompressed.read_exact(&mut hash_bytes) {
                    eprintln!("failed to read hash from stream: {}", e);
                    continue;
                }

                let hash = Hash::from_bytes(hash_bytes);

                println!(
                    "incoming file, accept? (y/n)\nname: {}\nsize: {}\nfrom: {}\nhash: {}",
                    name, size, address, hash
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

                let mut file = match File::create_new(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("failed to create file: {}", e);
                        continue;
                    }
                };

                println!("transfering file...");

                if let Err(e) = io::copy(&mut decompressed, &mut file) {
                    eprintln!("failed to copy from stream to file: {}", e);
                    continue;
                };

                let mut hasher = Hasher::new();

                hasher.update_mmap_rayon(&path)?;

                let out_hash = hasher.finalize();

                println!("saved to {}", name);

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
