use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::EnvFilter;

use mayrun::author;
use mayrun::mcp::MayrunServer;
use mayrun::packs;
use mayrun::policy::{Decision, default_policy_yaml, find_policy_path, load_policy};
use mayrun::receipts::{ReceiptLog, default_receipt_path};
use mayrun::shell::{RunError, Runner};

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
    /// Policy authoring helpers (offline; never auto-Allow at runtime)
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCmd {
    /// Draft a policy YAML from natural-language intent (review before use)
    Draft {
        /// Intent description
        intent: String,
    },
    /// Propose rule snippets from receipt history
    Tighten {
        #[arg(long)]
        receipts: Option<PathBuf>,
        /// Minimum times a pattern must appear
        #[arg(long, default_value_t = 2)]
        min_count: usize,
    },
    /// List built-in pack names
    Packs,
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
            let ev = compiled.evaluate_detailed(&command);
            println!(
                "{}",
                serde_json::json!({
                    "decision": ev.decision,
                    "rule_id": ev.rule_id,
                    "reason": ev.reason,
                    "capabilities": ev.capabilities,
                })
            );
            Ok(match ev.decision {
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
                Err(RunError::Denied { rule_id, reason }) => {
                    eprintln!(
                        "mayrun: denied by policy{}",
                        format_prov(rule_id.as_deref(), reason.as_deref())
                    );
                    Ok(ExitCode::from(3))
                }
                Err(RunError::ApprovalRequired { id, rule_id, reason }) => {
                    eprintln!(
                        "mayrun: approval required (receipt {id}){}. Re-run with --approve after confirming.",
                        format_prov(rule_id.as_deref(), reason.as_deref())
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
            let (allow, deny, require_approval) = compiled.counts_by_effect();
            println!("policy: {}", path.display());
            println!("default: {:?}", compiled.raw.default);
            println!(
                "rules: total={} allow={allow} deny={deny} require_approval={require_approval}",
                compiled.rule_count()
            );
            if !compiled.raw.extends.is_empty() {
                let packs: Vec<_> = compiled
                    .raw
                    .extends
                    .iter()
                    .map(|e| e.pack_name())
                    .collect();
                println!("extends: {}", packs.join(", "));
            }
            println!("receipts: {}", log.path().display());
            for r in log.recent(limit)? {
                println!(
                    "- {} {:?} rule={} executed={} exit={:?} cmd={}",
                    &r.id[..8.min(r.id.len())],
                    r.decision,
                    r.rule_id.as_deref().unwrap_or("-"),
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
        Commands::Policy { command } => match command {
            PolicyCmd::Draft { intent } => {
                let yaml = author::draft_policy(&intent).map_err(|e| anyhow::anyhow!(e))?;
                print!("{yaml}");
                if !yaml.ends_with('\n') {
                    println!();
                }
                Ok(ExitCode::SUCCESS)
            }
            PolicyCmd::Tighten {
                receipts,
                min_count,
            } => {
                let log = ReceiptLog::open(receipts.unwrap_or_else(default_receipt_path))?;
                let all = log.all()?;
                let yaml = author::tighten_from_receipts(&all, min_count.max(1));
                print!("{yaml}");
                Ok(ExitCode::SUCCESS)
            }
            PolicyCmd::Packs => {
                for name in packs::PACK_NAMES {
                    println!("{name}");
                }
                Ok(ExitCode::SUCCESS)
            }
        },
    }
}

fn format_prov(rule_id: Option<&str>, reason: Option<&str>) -> String {
    match (rule_id, reason) {
        (Some(id), Some(r)) => format!(" [{id}] {r}"),
        (Some(id), None) => format!(" [{id}]"),
        (None, Some(r)) => format!(" {r}"),
        (None, None) => String::new(),
    }
}

fn resolve_policy(explicit: Option<PathBuf>) -> Result<PathBuf> {
    find_policy_path(explicit.as_deref())
        .ok_or_else(|| anyhow::anyhow!("no policy found; run `mayrun init` first"))
}
