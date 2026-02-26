//! Serverless Job API commands
//!
//! Custom commands for RunPod's serverless execution API (`api.runpod.ai/v2`).
//! These are not auto-generated from OpenAPI since no spec is published.

use anyhow::{Context, Result};
use openapi_clap::clap::{self, Arg, ArgAction, Command};
use openapi_clap::reqwest::blocking::Client;
use openapi_clap::reqwest::Method;
use openapi_clap::{PreparedRequest, ResolvedAuth};
use serde_json::Value;

use crate::request::{self, ExecMode};

const SERVERLESS_BASE: &str = "https://api.runpod.ai/v2";

/// Build the `serverless` subcommand group.
pub fn build_command() -> Command {
    Command::new("serverless")
        .about("Run serverless jobs (api.runpod.ai/v2)")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("run")
                .about("Submit an async job")
                .arg(endpoint_id_arg())
                .arg(input_json_arg()),
        )
        .subcommand(
            Command::new("runsync")
                .about("Submit a sync job (blocks until complete)")
                .arg(endpoint_id_arg())
                .arg(input_json_arg())
                .arg(
                    Arg::new("wait")
                        .long("wait")
                        .help("Max wait time in ms (1000-300000, default: 90000)")
                        .action(ArgAction::Set)
                        .value_parser(clap::value_parser!(u32).range(1000..=300_000)),
                ),
        )
        .subcommand(
            Command::new("status")
                .about("Get job status and result")
                .arg(endpoint_id_arg())
                .arg(job_id_arg()),
        )
        .subcommand(
            Command::new("stream")
                .about("Get streaming output for a job")
                .arg(endpoint_id_arg())
                .arg(job_id_arg()),
        )
        .subcommand(
            Command::new("cancel")
                .about("Cancel a running or queued job")
                .arg(endpoint_id_arg())
                .arg(job_id_arg()),
        )
        .subcommand(
            Command::new("retry")
                .about("Retry a failed or timed-out job")
                .arg(endpoint_id_arg())
                .arg(job_id_arg()),
        )
        .subcommand(
            Command::new("purge-queue")
                .about("Remove all queued jobs from an endpoint")
                .arg(endpoint_id_arg()),
        )
        .subcommand(
            Command::new("health")
                .about("Check endpoint health and worker status")
                .arg(endpoint_id_arg()),
        )
}

/// Dispatch a serverless subcommand.
pub fn dispatch(
    client: &Client,
    api_key: &str,
    sub_name: &str,
    sub_matches: &clap::ArgMatches,
    mode: ExecMode,
) -> Result<Option<Value>> {
    let endpoint_id = sub_matches
        .get_one::<String>("endpoint-id")
        .context("endpoint-id is required")?;

    let req = match sub_name {
        "run" => {
            let input = parse_input(sub_matches)?;
            let body = serde_json::json!({ "input": input });
            let url = format!("{SERVERLESS_BASE}/{endpoint_id}/run");
            post(url, api_key, body)
        }
        "runsync" => {
            let input = parse_input(sub_matches)?;
            let body = serde_json::json!({ "input": input });
            let url = format!("{SERVERLESS_BASE}/{endpoint_id}/runsync");
            let mut req = post(url, api_key, body);
            if let Some(wait) = sub_matches.get_one::<u32>("wait") {
                req = req.query("wait", wait.to_string());
            }
            req
        }
        "status" => {
            let job_id = get_job_id(sub_matches)?;
            let url = format!("{SERVERLESS_BASE}/{endpoint_id}/status/{job_id}");
            get(url, api_key)
        }
        "stream" => {
            let job_id = get_job_id(sub_matches)?;
            let url = format!("{SERVERLESS_BASE}/{endpoint_id}/stream/{job_id}");
            get(url, api_key)
        }
        "cancel" => {
            let job_id = get_job_id(sub_matches)?;
            let url = format!("{SERVERLESS_BASE}/{endpoint_id}/cancel/{job_id}");
            post(url, api_key, serde_json::json!({}))
        }
        "retry" => {
            let job_id = get_job_id(sub_matches)?;
            let url = format!("{SERVERLESS_BASE}/{endpoint_id}/retry/{job_id}");
            post(url, api_key, serde_json::json!({}))
        }
        "purge-queue" => {
            let url = format!("{SERVERLESS_BASE}/{endpoint_id}/purge-queue");
            post(url, api_key, serde_json::json!({}))
        }
        "health" => {
            let url = format!("{SERVERLESS_BASE}/{endpoint_id}/health");
            get(url, api_key)
        }
        other => anyhow::bail!("unknown serverless command: {other}"),
    };

    request::execute(client, &req, mode)
}

fn get(url: String, api_key: &str) -> PreparedRequest {
    PreparedRequest::new(Method::GET, url).auth(ResolvedAuth::Bearer(api_key.to_string()))
}

fn post(url: String, api_key: &str, body: Value) -> PreparedRequest {
    PreparedRequest::new(Method::POST, url)
        .auth(ResolvedAuth::Bearer(api_key.to_string()))
        .body(body)
}

fn endpoint_id_arg() -> Arg {
    Arg::new("endpoint-id")
        .help("Serverless endpoint ID")
        .required(true)
}

fn job_id_arg() -> Arg {
    Arg::new("job-id").help("Job ID").required(true)
}

fn input_json_arg() -> Arg {
    Arg::new("input")
        .long("input")
        .short('i')
        .help("Job input as JSON string (supports @file and - for stdin)")
        .required(true)
        .action(ArgAction::Set)
}

fn parse_input(matches: &clap::ArgMatches) -> Result<Value> {
    let raw = matches
        .get_one::<String>("input")
        .context("--input is required")?;
    Ok(openapi_clap::resolve_json(raw)?)
}

fn get_job_id(matches: &clap::ArgMatches) -> Result<&String> {
    matches
        .get_one::<String>("job-id")
        .context("job-id is required")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse args against the serverless command tree.
    fn parse(args: &[&str]) -> clap::ArgMatches {
        build_command()
            .try_get_matches_from(args)
            .expect("failed to parse args")
    }

    // ── build_command structure ───────────────────────────────────

    #[test]
    fn subcommand_required() {
        let result = build_command().try_get_matches_from(["serverless"]);
        assert!(result.is_err(), "should require a subcommand");
    }

    #[test]
    fn unknown_subcommand_rejected() {
        let result = build_command().try_get_matches_from(["serverless", "unknown"]);
        assert!(result.is_err());
    }

    // ── run ───────────────────────────────────────────────────────

    #[test]
    fn run_parses_endpoint_and_input() {
        let m = parse(&["serverless", "run", "ep-123", "-i", r#"{"prompt":"hi"}"#]);
        let (name, sub) = m.subcommand().unwrap();
        assert_eq!(name, "run");
        assert_eq!(sub.get_one::<String>("endpoint-id").unwrap(), "ep-123");
        assert_eq!(
            sub.get_one::<String>("input").unwrap(),
            r#"{"prompt":"hi"}"#
        );
    }

    #[test]
    fn run_requires_endpoint_id() {
        let result =
            build_command().try_get_matches_from(["serverless", "run", "-i", r#"{"x":1}"#]);
        assert!(result.is_err());
    }

    #[test]
    fn run_requires_input() {
        let result = build_command().try_get_matches_from(["serverless", "run", "ep-123"]);
        assert!(result.is_err());
    }

    // ── runsync ───────────────────────────────────────────────────

    #[test]
    fn runsync_with_wait() {
        let m = parse(&[
            "serverless",
            "runsync",
            "ep-456",
            "-i",
            r#"{"x":1}"#,
            "--wait",
            "5000",
        ]);
        let (name, sub) = m.subcommand().unwrap();
        assert_eq!(name, "runsync");
        assert_eq!(sub.get_one::<u32>("wait").copied(), Some(5000));
    }

    #[test]
    fn runsync_wait_rejects_below_minimum() {
        let result = build_command().try_get_matches_from([
            "serverless",
            "runsync",
            "ep-456",
            "-i",
            r#"{"x":1}"#,
            "--wait",
            "500",
        ]);
        assert!(result.is_err(), "wait < 1000 should be rejected");
    }

    #[test]
    fn runsync_wait_rejects_above_maximum() {
        let result = build_command().try_get_matches_from([
            "serverless",
            "runsync",
            "ep-456",
            "-i",
            r#"{"x":1}"#,
            "--wait",
            "999999",
        ]);
        assert!(result.is_err(), "wait > 300000 should be rejected");
    }

    // ── status / stream / cancel / retry ──────────────────────────

    #[test]
    fn status_parses_endpoint_and_job_id() {
        let m = parse(&["serverless", "status", "ep-789", "job-abc"]);
        let (name, sub) = m.subcommand().unwrap();
        assert_eq!(name, "status");
        assert_eq!(sub.get_one::<String>("endpoint-id").unwrap(), "ep-789");
        assert_eq!(sub.get_one::<String>("job-id").unwrap(), "job-abc");
    }

    #[test]
    fn stream_parses_endpoint_and_job_id() {
        let m = parse(&["serverless", "stream", "ep-789", "job-def"]);
        let (_, sub) = m.subcommand().unwrap();
        assert_eq!(sub.get_one::<String>("job-id").unwrap(), "job-def");
    }

    #[test]
    fn cancel_requires_job_id() {
        let result = build_command().try_get_matches_from(["serverless", "cancel", "ep-789"]);
        assert!(result.is_err());
    }

    #[test]
    fn retry_parses_correctly() {
        let m = parse(&["serverless", "retry", "ep-789", "job-xyz"]);
        let (name, _) = m.subcommand().unwrap();
        assert_eq!(name, "retry");
    }

    // ── purge-queue / health ──────────────────────────────────────

    #[test]
    fn purge_queue_requires_only_endpoint() {
        let m = parse(&["serverless", "purge-queue", "ep-001"]);
        let (name, sub) = m.subcommand().unwrap();
        assert_eq!(name, "purge-queue");
        assert_eq!(sub.get_one::<String>("endpoint-id").unwrap(), "ep-001");
    }

    #[test]
    fn health_requires_only_endpoint() {
        let m = parse(&["serverless", "health", "ep-002"]);
        let (name, sub) = m.subcommand().unwrap();
        assert_eq!(name, "health");
        assert_eq!(sub.get_one::<String>("endpoint-id").unwrap(), "ep-002");
    }

    // ── dispatch URL construction (dry-run) ───────────────────────

    #[test]
    fn dispatch_run_builds_correct_url() {
        let m = parse(&["serverless", "run", "ep-test", "-i", r#"{"a":1}"#]);
        let (sub_name, sub_matches) = m.subcommand().unwrap();
        let client = Client::new();
        let result = dispatch(&client, "fake-key", sub_name, sub_matches, ExecMode::DryRun);
        // dry-run は None を返し、実際にHTTPリクエストは送信されない
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn dispatch_health_builds_correct_url() {
        let m = parse(&["serverless", "health", "ep-test"]);
        let (sub_name, sub_matches) = m.subcommand().unwrap();
        let client = Client::new();
        let result = dispatch(&client, "fake-key", sub_name, sub_matches, ExecMode::DryRun);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn dispatch_unknown_command_returns_error() {
        // dispatch に直接 unknown コマンド名を渡すと bail! される
        let m = parse(&["serverless", "health", "ep-test"]);
        let (_, sub_matches) = m.subcommand().unwrap();
        let client = Client::new();
        let result = dispatch(
            &client,
            "fake-key",
            "nonexistent",
            sub_matches,
            ExecMode::DryRun,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown serverless command"));
    }
}
