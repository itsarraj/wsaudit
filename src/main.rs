use std::process;

use clap::Parser;
use wsaudit::run_security_audit;

#[derive(Parser, Debug)]
#[command(
    name = "wsaudit",
    about = "Audits a WebSocket endpoint for Cross-Site WebSocket Hijacking (CSWSH) and RFC 6455 compliance",
    version
)]
struct Args {
    /// WebSocket endpoint URL to audit (e.g. ws://localhost:8080/socket or wss://api.example.com/ws)
    url: String,

    /// Output audit report as JSON for CI/CD gates
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let report = run_security_audit(&args.url).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        report.print_summary();
    }

    if report.has_vulnerabilities() {
        process::exit(1);
    }

    Ok(())
}
