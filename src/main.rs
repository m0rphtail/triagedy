//! triage — alert triage as a UNIX filter.
//!
//! JSONL alerts in, typed decisions out. The decision shape (Choice / Score /
//! Noul with calibrated confidence) mirrors TypeSafe's System One primitives,
//! so the same pipeline runs on a local Ollama model today and on Jev once
//! early access lands — one flag changes.

mod alert;
mod backends;
mod decision;
mod engine;
mod policy;
mod questions;
mod types;
mod util;

use anyhow::anyhow;
use backends::{BackendConfig, BackendKind, Backends};
use clap::{Args, Parser, Subcommand};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "triage",
    version,
    about = "Alert triage as a UNIX filter: JSONL alerts in, typed decisions out.",
    long_about = "Reads one security alert per line, asks a decision backend for a typed \
                  assessment (disposition, severity, false-positive probability, escalation, \
                  attack class), routes it to an action in plain code, and writes one JSON \
                  record per alert — in input order, with per-record error isolation.\n\n\
                  Backends: mock (offline, deterministic), ollama (local models), \
                  jev (TypeSafe System One API, early access)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Assess JSONL alerts from stdin (or --input); write one JSONL decision per alert.
    Run(RunArgs),
    /// Check the configured backend: reachability, model, live round trip.
    Doctor(DoctorArgs),
}

#[derive(Args, Debug)]
struct BackendArgs {
    /// Backend to use
    #[arg(long, default_value = "ollama", value_name = "mock|ollama|jev")]
    backend: String,
    /// Model name (defaults: qwen3.5:latest for ollama, jev-latest for jev)
    #[arg(long)]
    model: Option<String>,
    /// Ollama base URL
    #[arg(long, default_value = "http://127.0.0.1:11434")]
    ollama_url: String,
    /// TypeSafe System One endpoint
    #[arg(long, default_value = "https://api.typesafe.ai/v1/systemone")]
    typesafe_url: String,
    /// TypeSafe API key (falls back to the TYPESAFE_API_KEY env var)
    #[arg(long)]
    api_key: Option<String>,
    /// Per-request timeout, seconds
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,
}

#[derive(Args, Debug)]
struct RunArgs {
    #[command(flatten)]
    backend: BackendArgs,
    /// Read alerts from a file instead of stdin
    #[arg(long)]
    input: Option<PathBuf>,
    /// Write decisions to a file instead of stdout
    #[arg(long)]
    output: Option<PathBuf>,
    /// Parallel in-flight assessments (output order is always input order)
    #[arg(long, default_value_t = 4)]
    jobs: usize,
    /// Suppress the stderr summary line
    #[arg(long)]
    quiet: bool,
}

#[derive(Args, Debug)]
struct DoctorArgs {
    #[command(flatten)]
    backend: BackendArgs,
}

fn resolve_model(args: &BackendArgs, kind: BackendKind) -> String {
    match &args.model {
        Some(m) => m.clone(),
        None => match kind {
            BackendKind::Mock => "mock".to_string(),
            BackendKind::Ollama => "qwen3.5:latest".to_string(),
            BackendKind::Jev => "jev-latest".to_string(),
        },
    }
}

fn backend_config(args: &BackendArgs, kind: BackendKind) -> BackendConfig {
    BackendConfig {
        kind,
        model: resolve_model(args, kind),
        ollama_url: args.ollama_url.clone(),
        typesafe_url: args.typesafe_url.clone(),
        api_key: args
            .api_key
            .clone()
            .or_else(|| std::env::var("TYPESAFE_API_KEY").ok()),
        timeout_secs: args.timeout_secs,
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("triage: error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> anyhow::Result<i32> {
    match cli.command {
        Command::Run(args) => cmd_run(args).await,
        Command::Doctor(args) => cmd_doctor(args).await,
    }
}

async fn cmd_run(args: RunArgs) -> anyhow::Result<i32> {
    let kind = BackendKind::parse(&args.backend.backend).map_err(|e| anyhow!(e))?;
    let cfg = backend_config(&args.backend, kind);
    let backend = Backends::from_config(&cfg).map_err(|e| anyhow!(e))?;
    let model = cfg.model.clone();

    let input: Box<dyn BufRead> = match &args.input {
        Some(path) => Box::new(BufReader::new(
            File::open(path).map_err(|e| anyhow!("opening {}: {e}", path.display()))?,
        )),
        None => Box::new(BufReader::new(std::io::stdin())),
    };
    let mut out: Box<dyn Write> = match &args.output {
        Some(path) => Box::new(BufWriter::new(
            File::create(path).map_err(|e| anyhow!("creating {}: {e}", path.display()))?,
        )),
        None => Box::new(BufWriter::new(std::io::stdout())),
    };

    let started = Instant::now();
    let stats = engine::run(input, &mut out, &backend, kind.name(), &model, args.jobs).await?;
    out.flush().ok();

    if !args.quiet {
        eprintln!(
            "triage: {} records, {} ok, {} failed in {:.1}s (backend {}, model {})",
            stats.total,
            stats.ok,
            stats.failed,
            started.elapsed().as_secs_f64(),
            kind.name(),
            model
        );
    }

    Ok(if stats.failed > 0 { 1 } else { 0 })
}

async fn cmd_doctor(args: DoctorArgs) -> anyhow::Result<i32> {
    let kind = BackendKind::parse(&args.backend.backend).map_err(|e| anyhow!(e))?;
    let cfg = backend_config(&args.backend, kind);

    let lines: Result<Vec<String>, String> = match kind {
        BackendKind::Mock => Ok(vec![
            "mock backend: offline and deterministic; nothing to check".to_string(),
            "usage: triage run --backend mock < alerts.jsonl".to_string(),
        ]),
        BackendKind::Ollama => backends::ollama::doctor(&cfg).await,
        BackendKind::Jev => backends::jev::doctor(&cfg).await,
    };

    match lines {
        Ok(lines) => {
            for l in lines {
                println!("{l}");
            }
            Ok(0)
        }
        Err(e) => {
            eprintln!("triage doctor: FAIL: {e}");
            Ok(1)
        }
    }
}
