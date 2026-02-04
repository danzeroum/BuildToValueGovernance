
//! BuildToValue CLI Tool
//!
//! Command-line interface for interacting with BuildToValue API.
//!
//! # Installation
//!
//! ```bash
//! cargo install buildtovalue-cli
//! ```
//!
//! # Usage
//!
//! ```bash
//! # Validate text
//! btv validate "My CPF is 123.456.789-09" --session session_123
//!
//! # Batch validate from file
//! btv batch inputs.json --session session_123
//!
//! # Submit appeal
//! btv appeal verd_abc123 "This was test data"
//!
//! # Health check
//! btv health
//! ```

use clap::{Parser, Subcommand};
use buildtovalue::{Client, ValidateRequest, BatchValidateRequest, BatchInput, Profile, Context};
use colored::*;
use std::fs;
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "btv")]
#[command(about = "BuildToValue CLI - Ethical governance for AI", long_about = None)]
struct Cli {
    /// API key (can also use BUILDTOVALUE_API_KEY env var)
    #[arg(short, long, env = "BUILDTOVALUE_API_KEY")]
    api_key: String,
    
    /// Base URL (default: https://api.buildtovalue.com/v2)
    #[arg(long, default_value = "https://api.buildtovalue.com/v2")]
    base_url: String,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate text input
    Validate {
        /// Text to validate
        text: String,
        
        /// Session ID
        #[arg(short, long)]
        session: String,
        
        /// Profile (general, healthcare, financial, educational, research)
        #[arg(short, long, default_value = "general")]
        profile: String,
        
        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
        
        /// Show technical evidence
        #[arg(short, long)]
        evidence: bool,
    },
    
    /// Batch validate from JSON file
    Batch {
        /// Input file (JSON array of {id, text})
        file: String,
        
        /// Session ID
        #[arg(short, long)]
        session: String,
        
        /// Profile
        #[arg(short, long, default_value = "general")]
        profile: String,
    },
    
    /// Submit an appeal
    Appeal {
        /// Verdict ID to contest
        verdict_id: String,
        
        /// Reason for appeal
        reason: String,
    },
    
    /// Health check
    Health,
    
    /// Interactive mode
    Interactive {
        /// Session ID
        #[arg(short, long)]
        session: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    let client = Client::new(&cli.api_key)
        .with_base_url(&cli.base_url);
    
    match cli.command {
        Commands::Validate { text, session, profile, format, evidence } => {
            validate_command(&client, text, session, profile, format, evidence).await?;
        }
        Commands::Batch { file, session, profile } => {
            batch_command(&client, file, session, profile).await?;
        }
        Commands::Appeal { verdict_id, reason } => {
            appeal_command(&client, verdict_id, reason).await?;
        }
        Commands::Health => {
            health_command(&client).await?;
        }
        Commands::Interactive { session } => {
            interactive_mode(&client, session).await?;
        }
    }
    
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Command Handlers
// ═══════════════════════════════════════════════════════════════

async fn validate_command(
    client: &Client,
    text: String,
    session: String,
    profile: String,
    format: String,
    show_evidence: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let profile_enum = match profile.as_str() {
        "general" => Profile::General,
        "healthcare" => Profile::Healthcare,
        "financial" => Profile::Financial,
        "educational" => Profile::Educational,
        "research" => Profile::Research,
        _ => return Err("Invalid profile".into()),
    };
    
    let result = client.validate(ValidateRequest::builder(session)
        .text(text)
        .profile(profile_enum)
        .build()
    ).await?;
    
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    
    // Pretty text output
    println!("\n{}", "═══════════════════════════════════════════".bright_blue());
    println!("{}", "BuildToValue Validation Result".bright_blue().bold());
    println!("{}", "═══════════════════════════════════════════".bright_blue());
    
    let action_color = match result.action {
        buildtovalue::Action::Allow => "green",
        buildtovalue::Action::Educate => "yellow",
        buildtovalue::Action::Redact => "yellow",
        buildtovalue::Action::Log => "cyan",
        buildtovalue::Action::Block => "red",
    };
    
    println!("\n{}: {}", "Action".bold(), format!("{:?}", result.action).color(action_color).bold());
    println!("{}: {:.2}%", "Confidence".bold(), result.confidence * 100.0);
    println!("\n{}", "Rationale:".bold());
    println!("  {}", result.rationale);
    
    if result.mercy_applied {
        println!("\n{}", "⚖️  Mercy Applied:".yellow().bold());
        for factor in &result.mercy_factors {
            println!("  • {}", factor);
        }
    }
    
    if show_evidence {
        if let Some(evidence) = &result.technical_evidence {
            println!("\n{}", "Technical Evidence:".bold());
            println!("  Findings: {} (Critical: {})", evidence.finding_count, evidence.critical_count);
            println!("  Entropy: {:.2}", evidence.statistics.entropy);
            println!("  Has PII: {}", if evidence.has_pii { "Yes".red() } else { "No".green() });
            
            if !evidence.findings.is_empty() {
                println!("\n  {}:", "Findings".underline());
                for finding in &evidence.findings {
                    println!("    • {}: {} (confidence: {:.2})", 
                        finding.r#type.yellow(),
                        finding.location,
                        finding.confidence
                    );
                }
            }
        }
    }
    
    if let Some(appeal_info) = &result.appeal_info {
        if appeal_info.can_appeal {
            println!("\n{}", "ℹ️  You can appeal this decision".cyan());
            println!("   Use: btv appeal {} \"your reason\"", result.verdict_id);
        }
    }
    
    println!("\n{}: {}ms", "Processing Time".bold(), result.processing_time_ms);
    println!("{}: {}", "Verdict ID".bold(), result.verdict_id.bright_black());
    
    println!("\n{}", "═══════════════════════════════════════════".bright_blue());
    
    Ok(())
}

async fn batch_command(
    client: &Client,
    file: String,
    session: String,
    profile: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_content = fs::read_to_string(&file)?;
    let inputs: Vec<serde_json::Value> = serde_json::from_str(&file_content)?;
    
    let batch_inputs: Vec<BatchInput> = inputs.iter()
        .map(|v| BatchInput {
            id: v["id"].as_str().unwrap_or("unknown").to_string(),
            text: v["text"].as_str().unwrap_or("").to_string(),
            context: None,
        })
        .collect();
    
    let profile_enum = match profile.as_str() {
        "general" => Profile::General,
        "healthcare" => Profile::Healthcare,
        "financial" => Profile::Financial,
        "educational" => Profile::Educational,
        "research" => Profile::Research,
        _ => return Err("Invalid profile".into()),
    };
    
    println!("Processing {} inputs...", batch_inputs.len());
    
    let result = client.validate_batch(BatchValidateRequest {
        inputs: batch_inputs,
        session_id: session,
        profile: Some(profile_enum),
    }).await?;
    
    println!("\n{}", "Batch Results:".bold());
    println!("Batch ID: {}", result.batch_id);
    println!("Total time: {}ms", result.total_processing_time_ms);
    
    let mut blocked = 0;
    let mut warned = 0;
    let mut allowed = 0;
    
    for item in &result.results {
        match item.result.action {
            buildtovalue::Action::Block => {
                blocked += 1;
                println!("  {} {}: {}", "❌".red(), item.input_id, "BLOCKED".red());
            }
            buildtovalue::Action::Educate | buildtovalue::Action::Redact => {
                warned += 1;
                println!("  {} {}: {}", "⚠️ ".yellow(), item.input_id, "WARNING".yellow());
            }
            _ => {
                allowed += 1;
                println!("  {} {}: {}", "✅".green(), item.input_id, "ALLOWED".green());
            }
        }
    }
    
    println!("\nSummary:");
    println!("  Allowed: {}", allowed.to_string().green());
    println!("  Warned:  {}", warned.to_string().yellow());
    println!("  Blocked: {}", blocked.to_string().red());
    
    Ok(())
}

async fn appeal_command(
    client: &Client,
    verdict_id: String,
    reason: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Submitting appeal for verdict: {}", verdict_id);
    
    let appeal_id = client.submit_appeal(&verdict_id, &reason).await?;
    
    println!("\n{}", "✅ Appeal submitted successfully!".green().bold());
    println!("Appeal ID: {}", appeal_id.bright_cyan());
    println!("\nYour appeal will be reviewed within 24 hours.");
    println!("You will be notified via email when a decision is made.");
    
    Ok(())
}

async fn health_command(
    client: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Checking BuildToValue API health...");
    
    let health = client.health_check().await?;
    
    let status = health.get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    
    let status_colored = match status {
        "healthy" => status.green().bold(),
        "degraded" => status.yellow().bold(),
        "down" => status.red().bold(),
        _ => status.normal(),
    };
    
    println!("\nStatus: {}", status_colored);
    
    if let Some(version) = health.get("version") {
        println!("Version: {}", version.as_str().unwrap_or("unknown"));
    }
    
    if let Some(components) = health.get("components") {
        println!("\nComponents:");
        for (name, status) in components.as_object().unwrap() {
            let status_str = status.as_str().unwrap_or("unknown");
            let status_colored = match status_str {
                "healthy" => "✅".green(),
                "degraded" => "⚠️ ".yellow(),
                "down" => "❌".red(),
                _ => "❓".normal(),
            };
            println!("  {} {}: {}", status_colored, name, status_str);
        }
    }
    
    Ok(())
}

async fn interactive_mode(
    client: &Client,
    session: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{self, Write};
    
    println!("\n{}", "═══════════════════════════════════════════".bright_blue());
    println!("{}", "BuildToValue Interactive Mode".bright_blue().bold());
    println!("{}", "═══════════════════════════════════════════".bright_blue());
    println!("\nType 'exit' or 'quit' to exit");
    println!("Type 'help' for commands\n");
    
    loop {
        print!("btv> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        let input = input.trim();
        
        if input.is_empty() {
            continue;
        }
        
        if input == "exit" || input == "quit" {
            println!("Goodbye!");
            break;
        }
        
        if input == "help" {
            println!("\nCommands:");
            println!("  <text>       - Validate text");
            println!("  help         - Show this help");
            println!("  exit/quit    - Exit interactive mode");
            continue;
        }
        
        // Validate input
        let result = client.validate(ValidateRequest::builder(&session)
            .text(input)
            .build()
        ).await?;
        
        match result.action {
            buildtovalue::Action::Allow => {
                println!("  {} {}", "✅".green(), "Allowed".green());
            }
            buildtovalue::Action::Educate => {
                println!("  {} {}", "⚠️ ".yellow(), "Warning".yellow());
                println!("  {}", result.rationale.bright_black());
            }
            buildtovalue::Action::Block => {
                println!("  {} {}", "❌".red(), "Blocked".red());
                println!("  {}", result.rationale);
            }
            _ => {
                println!("  Action: {:?}", result.action);
            }
        }
        
        println!();
    }
    
    Ok(())
}