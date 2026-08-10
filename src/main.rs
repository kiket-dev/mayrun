use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::EnvFilter;

use mayrun::author;
use mayrun::ci;
use mayrun::detect;
use mayrun::license;
use mayrun::mcp::MayrunServer;
use mayrun::mcp_proxy;
use mayrun::metrics;
use mayrun::packs;
use mayrun::policy::{Decision, default_policy_yaml, find_policy_path, load_policy};
use mayrun::receipts::{ReceiptLog, default_receipt_path};
use mayrun::sandbox;
use mayrun::scoreboard;
use mayrun::setup::{self, AgentKind};
use mayrun::shell::{RunError, Runner};
use mayrun::shell_hook::{self, ShellKind};
use mayrun::ux;

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
        /// Detect project signals and select packs (never weakens dangerous-defaults)
        #[arg(long)]
        detect: bool,
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
        /// Sandbox execution: soft (default if flag present) or required
        #[arg(long, num_args = 0..=1, default_missing_value = "soft")]
        sandbox: Option<String>,
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
    /// Print shell eval script that gates commands (zsh/bash/fish)
    ShellHook {
        /// Shell kind (default: detect from $SHELL)
        #[arg(long)]
        shell: Option<String>,
    },
    /// Wrap an agent shell: `mayrun shell-wrap -- bash -lc 'cmd'`
    ShellWrap {
        /// Program and args after `--`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<OsString>,
    },
    /// Print or write MCP/config snippets for coding agents
    Setup {
        /// Agent: cursor | claude | opencode
        agent: String,
        /// Write/merge into the default project path (creates .bak)
        #[arg(long)]
        write: bool,
        /// Override write path
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Offline pack scoreboard over pinned corpus
    Scoreboard {
        #[arg(long, default_value = "tests/corpus.yaml")]
        corpus: PathBuf,
        #[arg(long)]
        json: bool,
        /// Exit non-zero if unsafe recall is below this (default 1.0)
        #[arg(long, default_value_t = 1.0)]
        min_recall: f64,
    },
    /// Offline governance metrics from local receipts
    Metrics {
        #[arg(long)]
        receipts: Option<PathBuf>,
        /// Only receipts newer than this duration (e.g. 7d, 24h)
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Start MCP stdio server (for Cursor / Claude / other hosts)
    Mcp {
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        receipts: Option<PathBuf>,
    },
    /// Thin MCP stdio proxy: gate upstream tools/call with policy + receipts
    McpProxy {
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        receipts: Option<PathBuf>,
        /// Label used for mcp.server matchers (default: upstream)
        #[arg(long, default_value = "upstream")]
        server_name: String,
        /// File listing approved tool names (one per line) for require_approval
        #[arg(long)]
        approve_file: Option<PathBuf>,
        /// Upstream MCP server command after `--`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        upstream: Vec<String>,
    },
    /// CI gate: Free = policy + advisory; Pro = receipt evidence (license)
    Ci {
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        receipts: Option<PathBuf>,
        /// Optional corpus for advisory scoreboard
        #[arg(long)]
        corpus: Option<PathBuf>,
        /// Pro license key (or set MAYRUN_LICENSE)
        #[arg(long)]
        license: Option<String>,
        /// Expected license subject (owner/repo); defaults to GITHUB_REPOSITORY
        #[arg(long)]
        repo: Option<String>,
        /// Fail closed as Pro even without parsing success path (needs license)
        #[arg(long)]
        pro: bool,
        #[arg(long)]
        json: bool,
        /// Emit GitHub Actions annotation commands
        #[arg(long)]
        github_annotations: bool,
    },
    /// Offline Pro license mint / verify (ed25519)
    License {
        #[command(subcommand)]
        command: LicenseCmd,
    },
    /// Policy authoring helpers (offline; never auto-Allow at runtime)
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
}

#[derive(Subcommand, Debug)]
enum LicenseCmd {
    /// Verify a license key offline
    Verify {
        /// License key (mr1.…); or omit to read MAYRUN_LICENSE
        key: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Mint a Pro license (requires MAYRUN_LICENSE_SIGNING_KEY hex)
    Mint {
        /// Subject: owner/repo or *
        #[arg(long, default_value = "*")]
        sub: String,
        /// Optional unix expiry seconds
        #[arg(long)]
        exp: Option<u64>,
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
        Commands::Init { force, detect } => {
            let path = PathBuf::from("mayrun.policy.yaml");
            if path.exists() && !force {
                bail!(
                    "{} already exists (pass --force to overwrite)",
                    path.display()
                );
            }
            let yaml = if detect {
                let root = std::env::current_dir()?;
                let det = detect::detect_packs(&root);
                for s in &det.signals {
                    eprintln!("detect: {s}");
                }
                eprintln!("detect: extends → {}", det.packs.join(", "));
                detect::policy_yaml_for_packs(&det.packs)
            } else {
                default_policy_yaml().to_string()
            };
            std::fs::write(&path, yaml)?;
            println!("wrote {}", path.display());
            if !force && detect {
                println!("tip: re-run with --force to overwrite after project changes");
            }
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
            sandbox: sandbox_flag,
        } => {
            let path = resolve_policy(policy)?;
            let compiled = load_policy(&path)?;
            let log = ReceiptLog::open(receipts.unwrap_or_else(default_receipt_path))?;
            let mode = sandbox::resolve_mode(sandbox_flag.as_deref())
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut runner = Runner::new(compiled, log).with_sandbox(mode);
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
                        "{}",
                        ux::format_denial(rule_id.as_deref(), reason.as_deref())
                    );
                    Ok(ExitCode::from(3))
                }
                Err(RunError::ApprovalRequired {
                    id,
                    rule_id,
                    reason,
                }) => {
                    eprintln!(
                        "{}",
                        ux::format_approval_required(
                            &command,
                            &id,
                            rule_id.as_deref(),
                            reason.as_deref(),
                        )
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
                println!("{}", ux::format_receipt_line(&r));
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::ShellHook { shell } => {
            let kind = match shell {
                Some(s) => ShellKind::parse(&s)
                    .ok_or_else(|| anyhow::anyhow!("unknown shell `{s}` (bash|zsh|fish)"))?,
                None => shell_hook::detect_shell(),
            };
            print!("{}", shell_hook::render_hook(kind, &shell_hook::mayrun_bin()));
            Ok(ExitCode::SUCCESS)
        }
        Commands::ShellWrap { argv } => {
            // Strip a leading `--` if present.
            let argv = if argv.first().is_some_and(|a| a == "--") {
                argv[1..].to_vec()
            } else {
                argv
            };
            shell_hook::shell_wrap(&argv)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Setup { agent, write, path } => {
            let kind = AgentKind::parse(&agent).ok_or_else(|| {
                anyhow::anyhow!("unknown agent `{agent}` (cursor|claude|opencode)")
            })?;
            let snippet = setup::render_snippet(kind);
            setup::validate_snippet(&snippet).map_err(|e| anyhow::anyhow!(e))?;
            if write {
                let dest = path.unwrap_or_else(|| {
                    setup::default_write_path(kind, std::path::Path::new("."))
                });
                setup::write_snippet(kind, &dest).map_err(|e| anyhow::anyhow!(e))?;
                println!("wrote {} (backup .bak if file existed)", dest.display());
            } else {
                eprintln!("# {} — paste into {}", kind.as_str(), snippet.path_hint);
                print!("{}", snippet.body);
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Scoreboard {
            corpus,
            json,
            min_recall,
        } => {
            let file = scoreboard::load_corpus(&corpus).map_err(|e| anyhow::anyhow!(e))?;
            let report = scoreboard::evaluate(&file).map_err(|e| anyhow::anyhow!(e))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", scoreboard::format_markdown(&report));
            }
            if report.recall_unsafe + f64::EPSILON < min_recall {
                bail!(
                    "recall {:.3} below min_recall {min_recall} ({} misses)",
                    report.recall_unsafe,
                    report.misses.len()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Metrics {
            receipts,
            since,
            json,
        } => {
            let log = ReceiptLog::open(receipts.unwrap_or_else(default_receipt_path))?;
            let all = log.all()?;
            let report =
                metrics::compute(&all, since.as_deref()).map_err(|e| anyhow::anyhow!(e))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", metrics::format_human(&report));
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
        Commands::McpProxy {
            policy,
            receipts,
            server_name,
            approve_file,
            upstream,
        } => {
            let mut upstream = upstream;
            if upstream.first().is_some_and(|a| a == "--") {
                upstream.remove(0);
            }
            let policy_path = resolve_policy(policy)?;
            let receipts_path = receipts.unwrap_or_else(default_receipt_path);
            mcp_proxy::run_proxy(mcp_proxy::ProxyOpts {
                policy_path,
                receipts_path,
                server_name,
                approve_file,
                upstream,
            })
            .context("mcp-proxy failed")?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Ci {
            policy,
            receipts,
            corpus,
            license,
            repo,
            pro,
            json,
            github_annotations,
        } => {
            let policy_path = resolve_policy(policy)?;
            let receipts_path = receipts.unwrap_or_else(default_receipt_path);
            let license = license.or_else(|| std::env::var("MAYRUN_LICENSE").ok());
            let repo_sub = repo.or_else(|| std::env::var("GITHUB_REPOSITORY").ok());
            let corpus = corpus.or_else(|| {
                let p = PathBuf::from("tests/corpus.yaml");
                if p.is_file() {
                    Some(p)
                } else {
                    None
                }
            });
            let report = ci::run(ci::CiOpts {
                policy: policy_path,
                receipts: receipts_path,
                corpus,
                license,
                repo_sub,
                force_pro: pro,
            })?;
            if github_annotations {
                ci::emit_github_annotations(&report);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", ci::format_human(&report));
            }
            Ok(if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Commands::License { command } => match command {
            LicenseCmd::Verify { key, repo } => {
                let key = key
                    .or_else(|| std::env::var("MAYRUN_LICENSE").ok())
                    .ok_or_else(|| {
                        anyhow::anyhow!("pass a license key or set MAYRUN_LICENSE")
                    })?;
                let repo = repo.or_else(|| std::env::var("GITHUB_REPOSITORY").ok());
                let verified = license::verify(&key, repo.as_deref(), None)?;
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "tier": verified.payload.tier,
                        "sub": verified.payload.sub,
                        "exp": verified.payload.exp,
                    })
                );
                Ok(ExitCode::SUCCESS)
            }
            LicenseCmd::Mint { sub, exp } => {
                let key = license::mint(&sub, exp).context(
                    "mint failed — set MAYRUN_LICENSE_SIGNING_KEY to a 32-byte hex seed",
                )?;
                println!("{key}");
                Ok(ExitCode::SUCCESS)
            }
        },
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

fn resolve_policy(explicit: Option<PathBuf>) -> Result<PathBuf> {
    find_policy_path(explicit.as_deref()).ok_or_else(|| {
        anyhow::anyhow!(
            "no policy found\n  fix: run `mayrun init` or `mayrun init --detect` in the project root, or pass --policy <path>"
        )
    })
}
