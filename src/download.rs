use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use anyhow::{bail, Context, Result};
use openapi_clap::clap::{Arg, ArgMatches, Command};
use openapi_clap::reqwest::blocking::Client;

use crate::ssh;

/// Base directory on the pod for download metadata.
const DL_BASE_DIR: &str = "/tmp/runpod-dl";

/// Build the `download` subcommand with add/status/list operations.
pub fn build_command() -> Command {
    Command::new("download")
        .about("Manage background downloads on a running pod")
        .long_about(
            "Register URLs for background download on a pod. Downloads continue \
             even after SSH disconnection. Use 'status' or 'list' to check progress.",
        )
        .subcommand_required(true)
        .subcommand(
            ssh::add_ssh_args(Command::new("add").about("Start a background download on a pod"))
                .arg(Arg::new("url").required(true).help("URL to download"))
                .arg(
                    Arg::new("dest")
                        .short('d')
                        .long("dest")
                        .value_name("PATH")
                        .help("Destination path on the pod (default: /workspace/<filename>)"),
                ),
        )
        .subcommand(
            ssh::add_ssh_args(Command::new("status").about("Check download progress")).arg(
                Arg::new("job_id")
                    .required(true)
                    .help("Download job ID (returned by 'add')"),
            ),
        )
        .subcommand(ssh::add_ssh_args(
            Command::new("list").about("List all downloads on a pod"),
        ))
}

/// Dispatch the download subcommand.
pub fn dispatch(
    client: &Client,
    api_key: &str,
    base_url: &str,
    matches: &ArgMatches,
) -> Result<Option<serde_json::Value>> {
    let (sub_name, sub_matches) = matches
        .subcommand()
        .context("no download operation provided")?;

    match sub_name {
        "add" => dispatch_add(client, api_key, base_url, sub_matches),
        "status" => dispatch_status(client, api_key, base_url, sub_matches),
        "list" => dispatch_list(client, api_key, base_url, sub_matches),
        _ => bail!("unknown download operation: {sub_name}"),
    }
}

// ── add ──

fn dispatch_add(
    client: &Client,
    api_key: &str,
    base_url: &str,
    matches: &ArgMatches,
) -> Result<Option<serde_json::Value>> {
    let target = ssh::resolve_target(client, api_key, base_url, matches)?;

    let url = matches
        .get_one::<String>("url")
        .context("url is required")?;

    let dest = matches
        .get_one::<String>("dest")
        .map(|s| s.to_string())
        .unwrap_or_else(|| output_from_url(url));

    let job_id = generate_job_id(url, &dest);
    let quoted_dl_dir = ssh::shell_quote(&format!("{DL_BASE_DIR}/{job_id}"));
    let quoted_url = ssh::shell_quote(url);
    let quoted_dest = ssh::shell_quote(&dest);

    // Remote script:
    // 1. Create job directory and write metadata files
    // 2. Check if same job is already running
    // 3. Start nohup wget in background
    //    - inner sh -c reads URL/output from files (avoids nested quoting)
    //    - writes exit code on completion
    let script = format!(
        r#"set -e
DL_DIR={quoted_dl_dir}
mkdir -p "$DL_DIR"
mkdir -p "$(dirname {quoted_dest})"
printf '%s\n' {quoted_url} > "$DL_DIR/url"
printf '%s\n' {quoted_dest} > "$DL_DIR/output"
if [ -f "$DL_DIR/pid" ]; then
  OLD_PID=$(cat "$DL_DIR/pid")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "ALREADY_RUNNING $OLD_PID"
    exit 0
  fi
fi
if ! command -v wget >/dev/null 2>&1; then
  echo "ERROR_NO_WGET"
  exit 1
fi
nohup sh -c '
  URL=$(cat "$0/url")
  OUTPUT=$(cat "$0/output")
  wget -c "$URL" -O "$OUTPUT" >"$0/log" 2>&1
  echo $? > "$0/exit"
' "$DL_DIR" >/dev/null 2>&1 &
echo $! > "$DL_DIR/pid"
echo "OK""#
    );

    let (stdout, stderr, exit_code) = ssh::ssh_exec(&target, &script)?;

    if exit_code != 0 {
        bail!(
            "failed to start download (exit {exit_code}): {}",
            stderr.trim()
        );
    }

    let stdout = stdout.trim();

    if stdout == "ERROR_NO_WGET" {
        bail!("wget not found on pod. Install with: apt-get install -y wget");
    }

    if let Some(rest) = stdout.strip_prefix("ALREADY_RUNNING") {
        let pid = rest.trim();
        return Ok(Some(serde_json::json!({
            "id": job_id,
            "state": "already_running",
            "pid": pid,
            "url": url,
            "output": dest,
        })));
    }

    Ok(Some(serde_json::json!({
        "id": job_id,
        "url": url,
        "output": dest,
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

    let quoted_dl_dir = ssh::shell_quote(&format!("{DL_BASE_DIR}/{job_id}"));

    // Remote script: read metadata files and check process state.
    // Output is key=value pairs, with LOG section delimited by markers.
    let script = format!(
        r#"DL_DIR={quoted_dl_dir}
if [ ! -d "$DL_DIR" ]; then echo "STATE=not_found"; exit 0; fi
PID=$(cat "$DL_DIR/pid" 2>/dev/null || echo "0")
URL=$(cat "$DL_DIR/url" 2>/dev/null || echo "")
OUTPUT=$(cat "$DL_DIR/output" 2>/dev/null || echo "")
if kill -0 "$PID" 2>/dev/null; then STATE=running; else STATE=done; fi
EXIT=$(cat "$DL_DIR/exit" 2>/dev/null || echo "-1")
SIZE=$(stat -c%s "$(echo "$OUTPUT" | tr -d '\n')" 2>/dev/null || echo "0")
echo "STATE=$STATE"
echo "PID=$PID"
echo "URL=$URL"
echo "OUTPUT=$OUTPUT"
echo "EXIT=$EXIT"
echo "SIZE=$SIZE"
echo "LOG_START"
tail -5 "$DL_DIR/log" 2>/dev/null || true
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
        bail!("download job not found: {job_id}");
    }

    Ok(Some(serde_json::json!({
        "id": job_id,
        "state": parsed.state,
        "pid": parsed.pid,
        "url": parsed.url,
        "output": parsed.output,
        "exit_code": parsed.exit_code,
        "file_size": parsed.file_size,
        "log": parsed.log,
    })))
}

/// Parsed output from the status remote script.
struct StatusOutput {
    state: String,
    pid: String,
    url: String,
    output: String,
    exit_code: String,
    file_size: String,
    log: String,
}

/// Parse key=value output from the status remote script.
fn parse_status_output(stdout: &str) -> StatusOutput {
    let mut state = String::new();
    let mut pid = String::from("0");
    let mut url = String::new();
    let mut output = String::new();
    let mut exit_code = String::from("-1");
    let mut file_size = String::from("0");
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
        } else if let Some(val) = line.strip_prefix("URL=") {
            url = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("OUTPUT=") {
            output = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("EXIT=") {
            exit_code = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("SIZE=") {
            file_size = val.trim().to_string();
        } else if line == "LOG_START" {
            in_log = true;
        }
    }

    StatusOutput {
        state,
        pid,
        url,
        output,
        exit_code,
        file_size,
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

    let quoted_base = ssh::shell_quote(DL_BASE_DIR);

    // Remote script: iterate job directories, output one TSV line per job.
    let script = format!(
        r#"BASE={quoted_base}
if [ ! -d "$BASE" ]; then exit 0; fi
for d in "$BASE"/*/; do
  [ -d "$d" ] || continue
  JOB_ID=$(basename "$d")
  PID=$(cat "$d/pid" 2>/dev/null || echo "0")
  URL=$(cat "$d/url" 2>/dev/null || echo "")
  OUTPUT=$(cat "$d/output" 2>/dev/null || echo "")
  if kill -0 "$PID" 2>/dev/null; then STATE=running; else STATE=done; fi
  EXIT=$(cat "$d/exit" 2>/dev/null || echo "-1")
  SIZE=$(stat -c%s "$(echo "$OUTPUT" | tr -d '\n')" 2>/dev/null || echo "0")
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$JOB_ID" "$STATE" "$PID" "$EXIT" "$SIZE" "$URL" "$OUTPUT"
done"#
    );

    let (stdout, stderr, exit_code) = ssh::ssh_exec(&target, &script)?;

    if exit_code != 0 {
        bail!(
            "failed to list downloads (exit {exit_code}): {}",
            stderr.trim()
        );
    }

    let jobs: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 7 {
                return None;
            }
            Some(serde_json::json!({
                "id": parts[0].trim(),
                "state": parts[1].trim(),
                "pid": parts[2].trim(),
                "exit_code": parts[3].trim(),
                "file_size": parts[4].trim(),
                "url": parts[5].trim(),
                "output": parts[6].trim(),
            }))
        })
        .collect();

    Ok(Some(serde_json::json!(jobs)))
}

// ── Utilities ──

/// Generate a deterministic job ID from URL and output path.
///
/// Uses `DefaultHasher` (SipHash with fixed keys) for a stable 12-char hex ID.
fn generate_job_id(url: &str, output: &str) -> String {
    let mut hasher = DefaultHasher::new();
    url.hash(&mut hasher);
    output.hash(&mut hasher);
    let full = format!("{:016x}", hasher.finish());
    full[..12].to_string()
}

/// Derive output path on the pod from a URL.
///
/// Extracts the filename from the URL path (stripping query parameters)
/// and places it under `/workspace/`.
fn output_from_url(url: &str) -> String {
    let path = url.split('?').next().unwrap_or(url);
    let filename = path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("download");
    format!("/workspace/{filename}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── generate_job_id ──

    #[test]
    fn job_id_is_deterministic() {
        let id1 = generate_job_id("https://example.com/file", "/workspace/file");
        let id2 = generate_job_id("https://example.com/file", "/workspace/file");
        assert_eq!(id1, id2);
    }

    #[test]
    fn job_id_differs_for_different_inputs() {
        let id1 = generate_job_id("https://example.com/a", "/workspace/a");
        let id2 = generate_job_id("https://example.com/b", "/workspace/b");
        assert_ne!(id1, id2);
    }

    #[test]
    fn job_id_is_12_hex_chars() {
        let id = generate_job_id("url", "output");
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── output_from_url ──

    #[test]
    fn output_from_url_extracts_filename() {
        assert_eq!(
            output_from_url("https://example.com/models/v1.safetensors"),
            "/workspace/v1.safetensors"
        );
    }

    #[test]
    fn output_from_url_strips_query_params() {
        assert_eq!(
            output_from_url("https://civitai.com/api/download/models/12345?type=Model"),
            "/workspace/12345"
        );
    }

    #[test]
    fn output_from_url_fallback_for_trailing_slash() {
        assert_eq!(
            output_from_url("https://example.com/"),
            "/workspace/download"
        );
    }

    #[test]
    fn output_from_url_huggingface() {
        assert_eq!(
            output_from_url("https://huggingface.co/user/repo/resolve/main/model.safetensors"),
            "/workspace/model.safetensors"
        );
    }

    // ── parse_status_output ──

    #[test]
    fn parse_running_status() {
        let output = "\
STATE=running
PID=12345
URL=https://example.com/model.bin
OUTPUT=/workspace/model.bin
EXIT=-1
SIZE=524288000
LOG_START
50% [====>     ] 524,288,000  10.5MB/s  eta 45s
LOG_END
";
        let parsed = parse_status_output(output);
        assert_eq!(parsed.state, "running");
        assert_eq!(parsed.pid, "12345");
        assert_eq!(parsed.url, "https://example.com/model.bin");
        assert_eq!(parsed.output, "/workspace/model.bin");
        assert_eq!(parsed.exit_code, "-1");
        assert_eq!(parsed.file_size, "524288000");
        assert!(parsed.log.contains("50%"));
    }

    #[test]
    fn parse_done_status() {
        let output = "\
STATE=done
PID=12345
URL=https://example.com/model.bin
OUTPUT=/workspace/model.bin
EXIT=0
SIZE=1048576000
LOG_START
100% [==========>] 1,048,576,000 done
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
URL=https://a.com/b
OUTPUT=/workspace/b
EXIT=-1
SIZE=0
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
    fn add_command_parses() {
        let cmd = build_command();
        let m =
            cmd.try_get_matches_from(["download", "add", "pod1", "https://example.com/model.bin"]);
        assert!(m.is_ok(), "add should parse: {m:?}");
    }

    #[test]
    fn add_command_with_dest() {
        let cmd = build_command();
        let m = cmd
            .try_get_matches_from([
                "download",
                "add",
                "pod1",
                "https://example.com/model.bin",
                "-d",
                "/workspace/custom.bin",
            ])
            .expect("should parse");
        let (_, sub) = m.subcommand().unwrap();
        assert_eq!(
            sub.get_one::<String>("dest").map(|s| s.as_str()),
            Some("/workspace/custom.bin")
        );
    }

    #[test]
    fn add_command_with_ssh_args() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from([
            "download",
            "add",
            "-i",
            "/tmp/key",
            "-l",
            "ubuntu",
            "pod1",
            "https://example.com/model.bin",
        ]);
        assert!(m.is_ok(), "add with SSH args should parse: {m:?}");
    }

    #[test]
    fn status_command_parses() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from(["download", "status", "pod1", "abc123def456"]);
        assert!(m.is_ok(), "status should parse: {m:?}");
    }

    #[test]
    fn list_command_parses() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from(["download", "list", "pod1"]);
        assert!(m.is_ok(), "list should parse: {m:?}");
    }

    #[test]
    fn requires_subcommand() {
        let cmd = build_command();
        let m = cmd.try_get_matches_from(["download"]);
        assert!(m.is_err(), "should require subcommand");
    }
}
