//! BuildToValue CLI (placeholder)
//! CLI será reativado na v1.9+.

use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(name = "btv")]
#[command(about = "BuildToValue CLI – temporariamente desativado", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate text input
    Validate { text: String },
    /// Health check
    Health,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Validate { text } => {
            println!("{}", "⚠️  CLI temporariamente desativado.".yellow().bold());
            println!("Use a API REST diretamente (FastAPI em http://localhost:8000).");
            println!("Texto recebido: {}", text);
        }
        Commands::Health => {
            println!("{}", "⚠️  CLI temporariamente desativado.".yellow().bold());
            println!("Use a API REST para health check.");
        }
    }

    Ok(())
}