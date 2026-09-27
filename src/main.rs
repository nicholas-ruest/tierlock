#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use tierlock::{Decision, HandoffReceipt, Itinerary, SealedItinerary};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Seal and verify authority-preserving execution itineraries"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Seal an itinerary with HMAC-SHA256.
    Seal {
        /// Unsealed itinerary JSON.
        #[arg(short, long)]
        contract: PathBuf,
        /// Destination for the sealed JSON bundle.
        #[arg(short, long)]
        output: PathBuf,
        /// Environment variable containing the HMAC key.
        #[arg(long, default_value = "TIERLOCK_KEY")]
        key_env: String,
    },
    /// Verify a sealed itinerary and its ordered JSONL handoff receipts.
    Verify {
        /// Sealed itinerary JSON.
        #[arg(short, long)]
        bundle: PathBuf,
        /// JSONL handoff receipts in execution order.
        #[arg(short, long)]
        receipts: PathBuf,
        /// Destination report, or stdout when omitted.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Override current Unix time in milliseconds for reproducible checks.
        #[arg(long)]
        now_ms: Option<u64>,
        /// Environment variable containing the HMAC key.
        #[arg(long, default_value = "TIERLOCK_KEY")]
        key_env: String,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("tierlock: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Seal {
            contract,
            output,
            key_env,
        } => {
            let key = read_key(&key_env)?;
            let contract: Itinerary = serde_json::from_reader(File::open(contract)?)?;
            let bundle = tierlock::seal(contract, key.as_bytes())?;
            write_json(&output, &bundle)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Verify {
            bundle,
            receipts,
            output,
            now_ms,
            key_env,
        } => {
            let key = read_key(&key_env)?;
            let bundle: SealedItinerary = serde_json::from_reader(File::open(bundle)?)?;
            let receipts = read_jsonl(&receipts)?;
            let now_ms = now_ms.unwrap_or(current_time_ms()?);
            let report = tierlock::verify(&bundle, &receipts, key.as_bytes(), now_ms)?;
            if let Some(path) = output {
                write_json(&path, &report)?;
            } else {
                serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
                println!();
            }
            Ok(if report.decision == Decision::Allow {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
    }
}

fn read_key(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name).map_err(|_| format!("environment variable {name} is not set"))?;
    if value.is_empty() {
        return Err(format!("environment variable {name} is empty").into());
    }
    Ok(value)
}

fn read_jsonl(path: &Path) -> Result<Vec<HandoffReceipt>, Box<dyn std::error::Error>> {
    let reader = BufReader::new(File::open(path)?);
    let mut receipts = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let receipt = serde_json::from_str(&line)
            .map_err(|error| format!("{}:{}: {error}", path.display(), index + 1))?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

fn write_json(
    path: &Path,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    writeln!(file)?;
    Ok(())
}

fn current_time_ms() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
