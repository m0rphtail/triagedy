//! triagedy — alert triage as a UNIX filter.
//!
//! JSONL alerts in, typed decisions out. The decision shape (Choice / Score /
//! Noul with calibrated confidence) mirrors TypeSafe's System One primitives,
//! so the same pipeline runs on a local Ollama model today and on Jev once
//! early access lands — one flag changes.

mod alert;
mod backends;
mod config;
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
    name = "triagedy",
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
    /// Store your TypeSafe API key securely (hidden input; written 0600, outside any repo).
    Init,
}

#[derive(Args, Debug)]
struct BackendArgs {
    /// Backend to use
    #[arg(long, default_value = "ollama", value_name = "mock|ollama|jev")]
    backend: String,
    /// Model name — whatever the backend serves: a local Ollama model sized to
    /// this machine, an Ollama cloud model, or the Jev model. Falls back to the
    /// TRIAGEDY_MODEL environment variable; no model is baked in.
    #[arg(long)]
    model: Option<String>,
    /// Ollama base URL
    #[arg(long, default_value = "http://127.0.0.1:11434")]
    ollama_url: String,
    /// TypeSafe System One endpoint
    #[arg(long, default_value = "https://api.typesafe.ai/v1/systemone")]
    typesafe_url: String,
    /// TypeSafe API key (prefer `triagedy init`: flags are visible to other
    /// processes). Falls back to $TYPESAFE_API_KEY, then the stored key file.
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

/// Resolve the model name. Nothing is pinned here on purpose: triagedy drives
/// whatever the backend serves — a local Ollama model that fits the machine, an
/// Ollama cloud model, or the Jev model — so the choice stays with the caller.
/// Resolution order: `--model`, then `$TRIAGEDY_MODEL`, then a backend default
/// where one exists (mock has no model; Jev has its service name).
fn resolve_model(args: &BackendArgs, kind: BackendKind) -> Result<String, String> {
    if let Some(model) = &args.model {
        return Ok(model.clone());
    }
    if let Ok(model) = std::env::var("TRIAGEDY_MODEL")
        && !model.trim().is_empty()
    {
        return Ok(model);
    }
    match kind {
        BackendKind::Mock => Ok("mock".to_string()),
        BackendKind::Jev => Ok("jev-latest".to_string()),
        BackendKind::Ollama => Err(
            "no model selected: pass --model <name> — any model the Ollama server serves, \
             local or cloud — or set TRIAGEDY_MODEL (`ollama list` shows local models)"
                .to_string(),
        ),
    }
}

fn backend_config(args: &BackendArgs, kind: BackendKind) -> Result<BackendConfig, String> {
    Ok(BackendConfig {
        kind,
        model: resolve_model(args, kind)?,
        ollama_url: args.ollama_url.clone(),
        typesafe_url: args.typesafe_url.clone(),
        api_key: args
            .api_key
            .clone()
            .or_else(|| std::env::var("TYPESAFE_API_KEY").ok())
            .or_else(|| config::load_key_from(&config::key_file())),
        timeout_secs: args.timeout_secs,
    })
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("triagedy: error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> anyhow::Result<i32> {
    match cli.command {
        Command::Run(args) => cmd_run(args).await,
        Command::Doctor(args) => cmd_doctor(args).await,
        Command::Init => cmd_init(),
    }
}

/// Store the TypeSafe API key in the user's config dir (0600, outside any
/// repo). Hidden prompt on a terminal, one line from stdin otherwise, so
/// `printf '%s\n' "$KEY" | triagedy init` works in automation.
fn cmd_init() -> anyhow::Result<i32> {
    let path = config::key_file();
    let updating = path.exists();

    let key = config::read_key_interactive().map_err(|e| anyhow!("reading key: {e}"))?;
    let key = key.trim().to_string();

    if key.is_empty() {
        eprintln!("triagedy init: no key entered — nothing stored");
        return Ok(1);
    }
    if key.chars().any(char::is_whitespace) {
        eprintln!(
            "triagedy init: the key contains whitespace mid-string — check the paste (nothing stored)"
        );
        return Ok(1);
    }

    config::store_key(&path, &key)
        .map_err(|e| anyhow!("storing key at {}: {e}", path.display()))?;

    let tail: String = key
        .chars()
        .skip(key.chars().count().saturating_sub(4))
        .collect();
    println!(
        "triagedy init: {} key (…{} chars, ends ...{tail}) at {} (mode 0600)",
        if updating { "updated" } else { "stored" },
        key.chars().count(),
        path.display()
    );
    println!("next: triagedy doctor --backend jev");
    Ok(0)
}

async fn cmd_run(args: RunArgs) -> anyhow::Result<i32> {
    let kind = BackendKind::parse(&args.backend.backend).map_err(|e| anyhow!(e))?;
    let cfg = backend_config(&args.backend, kind).map_err(|e| anyhow!(e))?;
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
            "triagedy: {} records, {} ok, {} failed in {:.1}s (backend {}, model {})",
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
    let cfg = backend_config(&args.backend, kind).map_err(|e| anyhow!(e))?;

    let lines: Result<Vec<String>, String> = match kind {
        BackendKind::Mock => Ok(vec![
            "mock backend: offline and deterministic; nothing to check".to_string(),
            "usage: triagedy run --backend mock < alerts.jsonl".to_string(),
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
            eprintln!("triagedy doctor: FAIL: {e}");
            Ok(1)
        }
    }
}
