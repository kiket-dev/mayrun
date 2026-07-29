mod mcp;
mod policy;
mod receipts;
mod shell;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::EnvFilter;

use crate::mcp::MayrunServer;
use crate::policy::{Decision, default_policy_yaml, find_policy_path, load_policy};
use crate::receipts::{ReceiptLog, default_receipt_path};
use crate::shell::Runner;

#[derive(Parser, Debug)]
#[command(
    name = "mayrun",
    about = "Policy gate for coding-agent side effects — may this run?",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Write a starter mayrun.policy.yaml in the current directory
    Init {
        /// Overwrite existing policy file
        #[arg(long)]
        force: bool,
    },
    /// Evaluate policy for a command (no execute)
    Check {
        /// Command string
        command: String,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Run a command if policy allows
    Run {
        /// Command string
        command: String,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        receipts: Option<PathBuf>,
        /// Confirm a require_approval decision (human only)
        #[arg(long)]
        approve: bool,
    },
    /// Show policy + recent receipts
    Status {
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        receipts: Option<PathBuf>,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Start MCP stdio server (for Cursor / Claude / other hosts)
    Mcp {
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        receipts: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = EnvFilter::from_default_env().add_directive("mayrun=info".parse().unwrap());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    match run().await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("mayrun: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { force } => {
            let path = PathBuf::from("mayrun.policy.yaml");
            if path.exists() && !force {
                bail!("{} already exists (pass --force to overwrite)", path.display());
            }
            std::fs::write(&path, default_policy_yaml())?;
            println!("wrote {}", path.display());
            Ok(ExitCode::SUCCESS)
        }
        Commands::Check { command, policy } => {
            let path = resolve_policy(policy)?;
            let compiled = load_policy(&path)?;
            let decision = compiled.evaluate(&command);
            println!("{decision:?}");
            Ok(match decision {
                Decision::Allow => ExitCode::SUCCESS,
                Decision::RequireApproval => ExitCode::from(2),
                Decision::Deny => ExitCode::from(3),
            })
        }
        Commands::Run {
            command,
            policy,
            receipts,
            approve,
        } => {
            let path = resolve_policy(policy)?;
            let compiled = load_policy(&path)?;
            let log = ReceiptLog::open(receipts.unwrap_or_else(default_receipt_path))?;
            let mut runner = Runner::new(compiled, log);
            match runner.run(&command, approve).await {
                Ok(result) => {
                    if !result.stdout.is_empty() {
                        print!("{}", result.stdout);
                    }
                    if !result.stderr.is_empty() {
                        eprint!("{}", result.stderr);
                    }
                    Ok(ExitCode::from(result.exit_code.clamp(0, 255) as u8))
                }
                Err(crate::shell::RunError::Denied) => {
                    eprintln!("mayrun: denied by policy");
                    Ok(ExitCode::from(3))
                }
                Err(crate::shell::RunError::ApprovalRequired { id }) => {
                    eprintln!(
                        "mayrun: approval required (receipt {id}). Re-run with --approve after confirming."
                    );
                    Ok(ExitCode::from(2))
                }
                Err(e) => Err(e.into()),
            }
        }
        Commands::Status {
            policy,
            receipts,
            limit,
        } => {
            let path = resolve_policy(policy)?;
            let compiled = load_policy(&path)?;
            let log = ReceiptLog::open(receipts.unwrap_or_else(default_receipt_path))?;
            println!("policy: {}", path.display());
            println!("default: {:?}", compiled.raw.default);
            println!(
                "rules: allow={} deny={} require_approval={}",
                compiled.raw.allow.len(),
                compiled.raw.deny.len(),
                compiled.raw.require_approval.len()
            );
            println!("receipts: {}", log.path().display());
            for r in log.recent(limit)? {
                println!(
                    "- {} {:?} executed={} exit={:?} cmd={}",
                    &r.id[..8.min(r.id.len())],
                    r.decision,
                    r.executed,
                    r.exit_code,
                    r.command
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Mcp { policy, receipts } => {
            let server = MayrunServer::try_new(policy, receipts)
                .context("failed to start mayrun MCP server")?;
            tracing::info!("mayrun MCP server starting (stdio)");
            let service = server.serve(stdio()).await?;
            service.waiting().await?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn resolve_policy(explicit: Option<PathBuf>) -> Result<PathBuf> {
    find_policy_path(explicit.as_deref())
        .ok_or_else(|| anyhow::anyhow!("no policy found; run `mayrun init` first"))
}
