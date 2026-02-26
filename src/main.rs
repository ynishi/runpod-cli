mod exec;
mod request;
mod serverless;

use anyhow::{Context, Result};
use openapi_clap::clap::{Arg, ArgAction};
use openapi_clap::reqwest::blocking::Client;
use openapi_clap::{build_commands, extract_operations, find_operation, Auth, CliConfig};
use openapi_deref::resolve;
use request::ExecMode;

/// RunPod OpenAPI spec embedded at compile time.
const SPEC_JSON: &str = include_str!("../runpod-openapi.json");

/// Default base URL for the REST API.
const DEFAULT_BASE_URL: &str = "https://rest.runpod.io/v1";

fn main() -> Result<()> {
    let raw_spec: serde_json::Value =
        serde_json::from_str(SPEC_JSON).context("failed to parse embedded OpenAPI spec")?;

    // Resolve all $ref pointers
    let resolved = resolve(&raw_spec).context("failed to resolve $ref in spec")?;
    let spec = resolved.value;

    // Extract operations from spec
    let operations = extract_operations(&spec);

    // Build clap command tree (auto-generated + custom serverless)
    let config = CliConfig::new(
        "runpod",
        "RunPod CLI — auto-generated from OpenAPI spec",
        DEFAULT_BASE_URL,
    );
    let cmd = build_commands(&config, &operations)
        .subcommand(exec::build_command())
        .subcommand(serverless::build_command())
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .global(true)
                .default_value("json")
                .help("Output format: json, compact"),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Print the request without sending"),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Print request/response details to stderr"),
        );
    let matches = cmd.get_matches();

    // Read API key
    let api_key =
        std::env::var("RUNPOD_API_KEY").context("RUNPOD_API_KEY environment variable not set")?;

    let base_url = matches
        .get_one::<String>("base-url")
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_BASE_URL);

    let output_format = matches
        .get_one::<String>("output")
        .map(|s| s.as_str())
        .unwrap_or("json");

    anyhow::ensure!(
        matches!(output_format, "json" | "compact"),
        "unsupported output format: {output_format} (expected: json, compact)"
    );

    let mode = if matches.get_flag("dry-run") {
        ExecMode::DryRun
    } else if matches.get_flag("verbose") {
        ExecMode::Verbose
    } else {
        ExecMode::Normal
    };

    // Find which group + operation was selected
    let (group_name, group_matches) = matches.subcommand().context("no subcommand provided")?;

    let client = Client::new();

    let result = if group_name == "exec" {
        // SSH exec (non-interactive command execution on pod)
        exec::dispatch(&client, &api_key, base_url, group_matches)?;
        None
    } else if group_name == "serverless" {
        // Serverless job API (custom commands)
        let (sub_name, sub_matches) = group_matches
            .subcommand()
            .context("no serverless operation provided")?;
        serverless::dispatch(&client, &api_key, sub_name, sub_matches, mode)?
    } else {
        // REST API (auto-generated from OpenAPI)
        let (op_name, op_matches) = group_matches
            .subcommand()
            .context("no operation provided")?;

        let op = find_operation(&operations, group_name, op_name, &config)
            .with_context(|| format!("operation not found: {group_name} {op_name}"))?;

        let req = request::from_operation(base_url, &Auth::Bearer(&api_key), op, op_matches)?;
        request::execute(&client, &req, mode)?
    };

    // Output (skip for dry-run)
    if let Some(value) = result {
        match output_format {
            "compact" => println!("{value}"),
            _ => println!("{}", serde_json::to_string_pretty(&value)?),
        }
    }

    Ok(())
}
