use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use anyhow::{bail, Context, Result};
use openapi_clap::clap::{Arg, ArgMatches, Command};
use openapi_clap::reqwest::blocking::Client;

use crate::ssh;

/// Base directory on the pod for task metadata.
const TASK_BASE_DIR: &str = "/tmp/runpod-task";

/// Build the `task` subcommand with run/status/list/log operations.
pub fn build_command() -> Command {
    Command::new("task")
        .about("Run shell commands in background on a pod")
        .long_about(
            "Run arbitrary shell commands as background tasks on a pod. \
             Tasks continue even after SSH disconnection. \
             Use 'status', 'list', or 'log' to monitor progress.",
        )
        .subcommand_required(true)
        .subcommand(
            ssh::add_ssh_args(Command::new("run").about("Start a background task on a pod"))
                .arg(
                    Arg::new("command")
                        .allow_hyphen_values(true)
                        .num_args(1..)
                        .last(true)
                        .help("Command to execute in background"),
                )
                .arg(Arg::new("script").long("script").value_name("FILE").help(
                    "Path to a local script file to upload and execute. \
                             The file is SCP'd to the pod and run via `sh`. \
                             Mutually exclusive with -- <command>.",
                ))
                .group(
                    openapi_clap::clap::ArgGroup::new("execution")
                        .args(["command", "script"])
                        .required(true),
                ),
        )
        .subcommand(
            ssh::add_ssh_args(Command::new("status").about("Check task status")).arg(
                Arg::new("job_id")
                    .required(true)
                    .help("Task job ID (returned by 'run')"),
            ),
        )
        .subcommand(ssh::add_ssh_args(
            Command::new("list").about("List all tasks on a pod"),
        ))
        .subcommand(
            ssh::add_ssh_args(Command::new("log").about("View task log output"))
                .arg(
                    Arg::new("job_id")
                        .required(true)
                        .help("Task job ID (returned by 'run')"),
                )
                .arg(
                    Arg::new("lines")
                        .short('n')
                        .long("lines")
                        .value_name("N")
                        .help("Number of lines from the end (default: full log)"),
                ),
        )
}

/// Dispatch the task subcommand.
pub fn dispatch(
    client: &Client,
    api_key: &str,
    base_url: &str,
    matches: &ArgMatches,
) -> Result<Option<serde_json::Value>> {
    let (sub_name, sub_matches) = matches.subcommand().context("no task operation provided")?;

    match sub_name {
        "run" => dispatch_run(client, api_key, base_url, sub_matches),
        "status" => dispatch_status(client, api_key, base_url, sub_matches),
        "list" => dispatch_list(client, api_key, base_url, sub_matches),
        "log" => dispatch_log(client, api_key, base_url, sub_matches),
        _ => bail!("unknown task operation: {sub_name}"),
    }
}

// ── run ──

fn dispatch_run(
    client: &Client,
    api_key: &str,
    base_url: &str,
    matches: &ArgMatches,
) -> Result<Option<serde_json::Value>> {
    let target = ssh::resolve_target(client, api_key, base_url, matches)?;

    // Determine execution mode: --script or -- <command>
    let script_file = matches.get_one::<String>("script");

    if let Some(script_path) = script_file {
        return dispatch_run_script(&target, script_path);
    }

    let command_parts: Vec<&str> = matches
        .get_many::<String>("command")
        .context("command is required")?
        .map(|s| s.as_str())
        .collect();
    let command = ssh::shell_join(&command_parts);

    let job_id = generate_job_id(&command);
    let quoted_task_dir = ssh::shell_quote(&format!("{TASK_BASE_DIR}/{job_id}"));
    let quoted_cmd = ssh::shell_quote(&command);

    let script = format!(
        r#"set -e
TASK_DIR={quoted_task_dir}
mkdir -p "$TASK_DIR"
printf '%s\n' {quoted_cmd} > "$TASK_DIR/run.sh"
printf '%s\n' {quoted_cmd} > "$TASK_DIR/cmd"
date +%s > "$TASK_DIR/started"
nohup sh -c '
  sh "$0/run.sh" >"$0/log" 2>&1
  echo $? > "$0/exit"
' "$TASK_DIR" >/dev/null 2>&1 &
echo $! > "$TASK_DIR/pid"
echo "OK""#
    );

    let (stdout, stderr, exit_code) = ssh::ssh_exec(&target, &script)?;

    if exit_code != 0 {
        bail!("failed to start task (exit {exit_code}): {}", stderr.trim());
    }

    let stdout = stdout.trim();

    if stdout != "OK" {
        bail!("unexpected response from pod: {stdout}");
    }

    Ok(Some(serde_json::json!({
        "id": job_id,
        "command": command,
    })))
}

/// Script-file execution mode: SCP the script to the pod, then run it as a background task.
///
/// Flow:
/// 1. Generate job_id from script content hash
/// 2. SCP local file → `/tmp/runpod-task/{job_id}/script.sh`
/// 3. Background-execute via nohup: `sh script.sh > log 2>&1`
/// 4. Return job_id for status/log polling
fn dispatch_run_script(
    target: &ssh::SshTarget,
    local_script_path: &str,
) -> Result<Option<serde_json::Value>> {
    let local_path = std::path::Path::new(local_script_path);
    if !local_path.exists() {
        bail!("script file not found: {local_script_path}");
    }

    let content = std::fs::read_to_string(local_path)
        .with_context(|| format!("failed to read script: {local_script_path}"))?;

    let job_id = generate_job_id(&content);
    let task_dir = format!("{TASK_BASE_DIR}/{job_id}");
    let remote_script = format!("{task_dir}/run.sh");

    let quoted_task_dir = ssh::shell_quote(&task_dir);
    let quoted_cmd = ssh::shell_quote(&format!("script: {local_script_path}"));

    // The bootstrap command runs after SCP upload completes.
    // It records metadata and starts the script in background.
    let bootstrap = format!(
        r#"set -e
TASK_DIR={quoted_task_dir}
mkdir -p "$TASK_DIR"
printf '%s\n' {quoted_cmd} > "$TASK_DIR/cmd"
date +%s > "$TASK_DIR/started"
nohup sh -c '
  sh "$0/run.sh" >"$0/log" 2>&1
  echo $? > "$0/exit"
' "$TASK_DIR" >/dev/null 2>&1 &
echo $! > "$TASK_DIR/pid"
echo "OK""#
    );

    let (stdout, stderr, exit_code) =
        ssh::ssh_upload_and_exec(target, local_path, &remote_script, &bootstrap)?;

    if exit_code != 0 {
        bail!(
            "failed to start script task (exit {exit_code}): {}",
            stderr.trim()
        );
    }

    let stdout = stdout.trim();
    if stdout != "OK" {
        bail!("unexpected response from pod: {stdout}");
    }

    Ok(Some(serde_json::json!({
        "id": job_id,
        "command": format!("script: {local_script_path}"),
    })))
}

// ── status ──

fn dispatch_status(
    client: &Client,
    api_key: &str,
    base_url: &str,
    matches: &ArgMatches,
) -> Result<Option<serde_json::Value>> {
    let target = ssh::resolve_target(client, api_key, base_url, matches)?;

    let job_id = matches
        .get_one::<String>("job_id")
        .context("job_id is required")?;
    ssh::validate_job_id(job_id)?;

    let quoted_task_dir = ssh::shell_quote(&format!("{TASK_BASE_DIR}/{job_id}"));

    let script = format!(
        r#"TASK_DIR={quoted_task_dir}
if [ ! -d "$TASK_DIR" ]; then echo "STATE=not_found"; exit 0; fi
PID=$(cat "$TASK_DIR/pid" 2>/dev/null || echo "0")
CMD=$(cat "$TASK_DIR/cmd" 2>/dev/null || echo "")
STARTED=$(cat "$TASK_DIR/started" 2>/dev/null || echo "0")
if kill -0 "$PID" 2>/dev/null; then STATE=running; else STATE=done; fi
EXIT=$(cat "$TASK_DIR/exit" 2>/dev/null || echo "-1")
echo "STATE=$STATE"
echo "PID=$PID"
echo "CMD=$CMD"
echo "STARTED=$STARTED"
echo "EXIT=$EXIT"
echo "LOG_START"
tail -5 "$TASK_DIR/log" 2>/dev/null || true
echo "LOG_END""#
    );

    let (stdout, stderr, exit_code) = ssh::ssh_exec(&target, &script)?;

    if exit_code != 0 {
        bail!(
            "failed to check status (exit {exit_code}): {}",
            stderr.trim()
        );
    }

    let parsed = parse_status_output(&stdout);

    if parsed.state == "not_found" {
        bail!("task not found: {job_id}");
    }

    Ok(Some(serde_json::json!({
        "id": job_id,
        "state": parsed.state,
        "pid": parsed.pid,
        "command": parsed.command,
        "started": parsed.started,
        "exit_code": parsed.exit_code,
        "log_tail": parsed.log,
    })))
}

/// Parsed output from the status remote script.
struct StatusOutput {
    state: String,
    pid: String,
    command: String,
    started: String,
    exit_code: String,
    log: String,
}

/// Parse key=value output from the status remote script.
fn parse_status_output(stdout: &str) -> StatusOutput {
    let mut state = String::new();
    let mut pid = String::from("0");
    let mut command = String::new();
    let mut started = String::from("0");
    let mut exit_code = String::from("-1");
    let mut log_lines: Vec<&str> = Vec::new();
    let mut in_log = false;

    for line in stdout.lines() {
        if in_log {
            if line == "LOG_END" {
                in_log = false;
            } else {
                log_lines.push(line);
            }
        } else if let Some(val) = line.strip_prefix("STATE=") {
            state = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("PID=") {
            pid = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("CMD=") {
            command = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("STARTED=") {
            started = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("EXIT=") {
            exit_code = val.trim().to_string();
        } else if line == "LOG_START" {
            in_log = true;
        }
    }

    StatusOutput {
        state,
        pid,
        command,
        started,
        exit_code,
        log: log_lines.join("\n"),
    }
}

// ── list ──

fn dispatch_list(
    client: &Client,
    api_key: &str,
    base_url: &str,
    matches: &ArgMatches,
) -> Result<Option<serde_json::Value>> {
    let target = ssh::resolve_target(client, api_key, base_url, matches)?;

    let quoted_base = ssh::shell_quote(TASK_BASE_DIR);

    let script = format!(
        r#"BASE={quoted_base}
if [ ! -d "$BASE" ]; then exit 0; fi
for d in "$BASE"/*/; do
  [ -d "$d" ] || continue
  JOB_ID=$(basename "$d")
  PID=$(cat "$d/pid" 2>/dev/null || echo "0")
  CMD=$(cat "$d/cmd" 2>/dev/null || echo "")
  STARTED=$(cat "$d/started" 2>/dev/null || echo "0")
  if kill -0 "$PID" 2>/dev/null; then STATE=running; else STATE=done; fi
  EXIT=$(cat "$d/exit" 2>/dev/null || echo "-1")
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$JOB_ID" "$STATE" "$PID" "$EXIT" "$STARTED" "$CMD"
done"#
    );

    let (stdout, stderr, exit_code) = ssh::ssh_exec(&target, &script)?;

    if exit_code != 0 {
        bail!("failed to list tasks (exit {exit_code}): {}", stderr.trim());
    }

    let jobs: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(6, '\t').collect();
            if parts.len() < 6 {
                return None;
            }
            Some(serde_json::json!({
                "id": parts[0].trim(),
                "state": parts[1].trim(),
                "pid": parts[2].trim(),
                "exit_code": parts[3].trim(),
                "started": parts[4].trim(),
                "command": parts[5].trim(),
            }))
        })
        .collect();

    Ok(Some(serde_json::json!(jobs)))
}

// ── log ──

fn dispatch_log(
    client: &Client,
    api_key: &str,
    base_url: &str,
    matches: &ArgMatches,
) -> Result<Option<serde_json::Value>> {
    let target = ssh::resolve_target(client, api_key, base_url, matches)?;

    let job_id = matches
        .get_one::<String>("job_id")
        .context("job_id is required")?;
    ssh::validate_job_id(job_id)?;

    let lines: Option<u64> = matches
        .get_one::<String>("lines")
        .map(|n| n.parse::<u64>())
        .transpose()
        .context("--lines must be a positive integer")?;

    let quoted_task_dir = ssh::shell_quote(&format!("{TASK_BASE_DIR}/{job_id}"));

    let cat_cmd = match lines {
        Some(n) => format!("tail -n {n} \"$TASK_DIR/log\" 2>/dev/null || true"),
        None => "cat \"$TASK_DIR/log\" 2>/dev/null || true".to_string(),
    };

    let script = format!(
        r#"TASK_DIR={quoted_task_dir}
if [ ! -d "$TASK_DIR" ]; then echo "STATE=not_found"; exit 0; fi
echo "STATE=ok"
echo "LOG_START"
{cat_cmd}
echo "LOG_END""#
    );

    let (stdout, stderr, exit_code) = ssh::ssh_exec(&target, &script)?;

    if exit_code != 0 {
        bail!("failed to read log (exit {exit_code}): {}", stderr.trim());
    }

    // Parse STATE and LOG
    let mut state = String::new();
    let mut log_lines: Vec<&str> = Vec::new();
    let mut in_log = false;

    for line in stdout.lines() {
        if in_log {
            if line == "LOG_END" {
                in_log = false;
            } else {
                log_lines.push(line);
            }
        } else if let Some(val) = line.strip_prefix("STATE=") {
            state = val.trim().to_string();
        } else if line == "LOG_START" {
            in_log = true;
        }
    }

    if state == "not_found" {
        bail!("task not found: {job_id}");
    }

    Ok(Some(serde_json::json!({
        "id": job_id,
        "log": log_lines.join("\n"),
    })))
}

// ── Utilities ──

/// Generate a job ID from command string and current time.
///
/// Uses `DefaultHasher` (SipHash with fixed keys) plus nanosecond timestamp
/// to produce a unique 12-char hex ID. Unlike download jobs, task jobs are
/// not idempotent — the same command can be run multiple times.
fn generate_job_id(command: &str) -> String {
    let mut hasher = DefaultHasher::new();
    command.hash(&mut hasher);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    let full = format!("{:016x}", hasher.finish());
    full[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── generate_job_id ──

    #[test]
    fn job_id_is_12_hex_chars() {
        let id = generate_job_id("pip install torch");
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn job_id_differs_across_calls() {
        let id1 = generate_job_id("echo hello");
        // Tiny sleep to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(1));
        let id2 = generate_job_id("echo hello");
        assert_ne!(id1, id2, "same command should produce different IDs");
    }

    // ── parse_status_output ──

    #[test]
    fn parse_running_status() {
        let output = "\
STATE=running
PID=12345
CMD=pip install torch
STARTED=1709600000
EXIT=-1
LOG_START
Installing torch...
LOG_END
";
        let parsed = parse_status_output(output);
        assert_eq!(parsed.state, "running");
        assert_eq!(parsed.pid, "12345");
        assert_eq!(parsed.command, "pip install torch");
        assert_eq!(parsed.started, "1709600000");
        assert_eq!(parsed.exit_code, "-1");
        assert!(parsed.log.contains("Installing torch"));
    }

    #[test]
    fn parse_done_status() {
        let output = "\
STATE=done
PID=12345
CMD=echo hello
STARTED=1709600000
EXIT=0
LOG_START
hello
LOG_END
";
        let parsed = parse_status_output(output);
        assert_eq!(parsed.state, "done");
        assert_eq!(parsed.exit_code, "0");
    }

    #[test]
    fn parse_not_found_status() {
        let output = "STATE=not_found\n";
        let parsed = parse_status_output(output);
        assert_eq!(parsed.state, "not_found");
    }

    #[test]
    fn parse_status_with_multiline_log() {
        let output = "\
STATE=running
PID=99
CMD=bash setup.sh
STARTED=1709600000
EXIT=-1
LOG_START
line1
line2
line3
LOG_END
";
        let parsed = parse_status_output(output);
        assert_eq!(parsed.log, "line1\nline2\nline3");
    }

    // ── build_command ──

    #[test]
    fn run_command_parses() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from(["task", "run", "pod1", "--", "pip", "install", "torch"]);
        assert!(m.is_ok(), "run should parse: {m:?}");
    }

    #[test]
    fn run_command_with_ssh_args() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from([
            "task", "run", "-i", "/tmp/key", "-l", "ubuntu", "pod1", "--", "echo", "hello",
        ]);
        assert!(m.is_ok(), "run with SSH args should parse: {m:?}");
    }

    #[test]
    fn status_command_parses() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from(["task", "status", "pod1", "abc123def456"]);
        assert!(m.is_ok(), "status should parse: {m:?}");
    }

    #[test]
    fn list_command_parses() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from(["task", "list", "pod1"]);
        assert!(m.is_ok(), "list should parse: {m:?}");
    }

    #[test]
    fn log_command_parses() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from(["task", "log", "pod1", "abc123def456"]);
        assert!(m.is_ok(), "log should parse: {m:?}");
    }

    #[test]
    fn log_command_with_lines() {
        let cmd = build_command();
        let m = cmd
            .try_get_matches_from(["task", "log", "pod1", "abc123def456", "-n", "50"])
            .expect("should parse");
        let (_, sub) = m.subcommand().unwrap();
        assert_eq!(
            sub.get_one::<String>("lines").map(|s| s.as_str()),
            Some("50")
        );
    }

    #[test]
    fn run_script_parses() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from(["task", "run", "--script", "/tmp/inspect.sh", "pod1"]);
        assert!(m.is_ok(), "run --script should parse: {m:?}");
        let binding = m.unwrap();
        let (_, sub) = binding.subcommand().unwrap();
        assert_eq!(
            sub.get_one::<String>("script").map(|s| s.as_str()),
            Some("/tmp/inspect.sh")
        );
    }

    #[test]
    fn run_script_with_ssh_args() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from([
            "task",
            "run",
            "-i",
            "/tmp/key",
            "--script",
            "/tmp/test.sh",
            "pod1",
        ]);
        assert!(m.is_ok(), "run --script with SSH args should parse: {m:?}");
    }

    #[test]
    fn run_rejects_both_script_and_command() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from([
            "task",
            "run",
            "--script",
            "/tmp/test.sh",
            "pod1",
            "--",
            "echo",
            "hello",
        ]);
        assert!(m.is_err(), "should reject both --script and -- command");
    }

    #[test]
    fn run_requires_script_or_command() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from(["task", "run", "pod1"]);
        assert!(m.is_err(), "should require either --script or -- command");
    }

    #[test]
    fn requires_subcommand() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from(["task"]);
        assert!(m.is_err(), "should require subcommand");
    }
}
