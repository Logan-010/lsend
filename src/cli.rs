use clap::{Parser, ValueEnum, value_parser};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"))]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
pub struct Cli {
    /// Port to listen on
    #[arg(long, short = 'P', required = false, default_value_t = 0)]
    pub port: u16,

    /// Compression level
    #[arg(long, short = 'L', required = false, default_value_t = 1, value_parser = value_parser!(u32).range(1..=9))]
    pub level: u32,

    /// Sets app mode
    #[arg(long, short = 'M', required = true)]
    pub mode: Mode,

    /// Id of client to connect to (only needed in share mode)
    #[arg(long, short = 'I', required = false)]
    pub id: Option<String>,

    /// File to share or folder to save to
    pub path: PathBuf,
}

#[derive(Clone, ValueEnum)]
pub enum Mode {
    Share,
    Save,
}
