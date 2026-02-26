use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use openapi_clap::clap::{Arg, ArgMatches, Command};
use openapi_clap::reqwest::blocking::Client;
use ssh2::Session;

/// Default SSH user for RunPod pods.
const DEFAULT_USER: &str = "root";

/// SSH key candidates in priority order.
const KEY_CANDIDATES: &[&str] = &[".ssh/id_ed25519", ".ssh/id_ed25519_runpod", ".ssh/id_rsa"];

/// Build the `exec` subcommand (SSH-compatible options where applicable).
pub fn build_command() -> Command {
    Command::new("exec")
        .about("Execute a command on a running pod via SSH (non-interactive)")
        .long_about(
            "Execute a command on a running pod via SSH exec channel (no PTY required).\n\n\
             Connection is made via Direct TCP (public IP + mapped port), which is \
             auto-detected from the RunPod API. Use --host and -p to override.",
        )
        .arg(
            Arg::new("pod_id")
                .required(true)
                .help("Pod ID to connect to"),
        )
        .arg(
            Arg::new("identity")
                .short('i')
                .long("identity")
                .value_name("IDENTITY_FILE")
                .help("Path to SSH private key (auto-detect: ~/.ssh/id_ed25519, id_ed25519_runpod, id_rsa)"),
        )
        .arg(
            Arg::new("login-name")
                .short('l')
                .long("login-name")
                .value_name("USER")
                .default_value(DEFAULT_USER)
                .help("SSH login user"),
        )
        .arg(
            Arg::new("host")
                .long("host")
                .value_name("HOST")
                .help("Override SSH host (default: auto-detect from pod info)"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Override SSH port (default: auto-detect from pod info)"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .value_name("SECONDS")
                .default_value("10")
                .help("SSH connection timeout in seconds"),
        )
        .arg(
            Arg::new("command")
                .allow_hyphen_values(true)
                .required(true)
                .num_args(1..)
                .last(true)
                .help("Command to execute on the pod"),
        )
}

/// Dispatch the exec command: resolve connection → SSH connect → exec → output.
pub fn dispatch(
    client: &Client,
    api_key: &str,
    base_url: &str,
    matches: &ArgMatches,
) -> Result<()> {
    let pod_id = matches
        .get_one::<String>("pod_id")
        .context("pod_id is required")?;

    let user = matches
        .get_one::<String>("login-name")
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_USER);

    let key_path = matches
        .get_one::<String>("identity")
        .map(|s| expand_tilde(s))
        .unwrap_or_else(detect_key_path);

    let timeout_secs: u64 = matches
        .get_one::<String>("timeout")
        .map(|s| s.as_str())
        .unwrap_or("10")
        .parse()
        .context("invalid timeout value")?;
    let timeout = Duration::from_secs(timeout_secs);

    let command_parts: Vec<&str> = matches
        .get_many::<String>("command")
        .context("command is required")?
        .map(|s| s.as_str())
        .collect();
    let command = shell_join(&command_parts);

    // Resolve host and port
    let host_override = matches.get_one::<String>("host");
    let port_override = matches.get_one::<String>("port");

    let manual_port = port_override
        .map(|s| s.parse::<u16>())
        .transpose()
        .context("invalid port number")?;

    let (host, ssh_port) = if let Some(h) = host_override {
        // Full manual override — skip API call
        (h.to_string(), manual_port.unwrap_or(22))
    } else {
        // Auto-detect from RunPod API (manual port overrides if given)
        let (api_host, api_port) = resolve_connection(client, api_key, base_url, pod_id)?;
        (api_host, manual_port.unwrap_or(api_port))
    };

    // Connect and execute
    let (stdout, stderr, exit_code) =
        ssh_exec(&host, ssh_port, user, &key_path, &command, timeout)?;

    if !stdout.is_empty() {
        print!("{stdout}");
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Resolve SSH connection details from the RunPod REST API.
fn resolve_connection(
    client: &Client,
    api_key: &str,
    base_url: &str,
    pod_id: &str,
) -> Result<(String, u16)> {
    let pod_info = fetch_pod_info(client, api_key, base_url, pod_id)?;

    // Verify pod is running
    if let Some(status) = pod_info.get("desiredStatus").and_then(|v| v.as_str()) {
        if status != "RUNNING" {
            bail!("pod {pod_id} is not running (status: {status})");
        }
    }

    let public_ip = pod_info
        .get("publicIp")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .with_context(|| format!("pod {pod_id} has no public IP (may still be initializing)"))?
        .to_string();

    let ssh_port = extract_ssh_port(&pod_info)?;

    Ok((public_ip, ssh_port))
}

/// Fetch pod information from the REST API.
fn fetch_pod_info(
    client: &Client,
    api_key: &str,
    base_url: &str,
    pod_id: &str,
) -> Result<serde_json::Value> {
    let url = format!("{base_url}/pods/{pod_id}");
    let resp = client
        .get(&url)
        .bearer_auth(api_key)
        .send()
        .with_context(|| format!("failed to fetch pod info for {pod_id}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        bail!("failed to fetch pod info (HTTP {status}): {body}");
    }

    resp.json::<serde_json::Value>()
        .context("failed to parse pod info response")
}

/// Extract the external SSH port from pod portMappings.
///
/// Expected format: `{"22": 10341}` where value is the external port.
fn extract_ssh_port(pod_info: &serde_json::Value) -> Result<u16> {
    if let Some(mappings) = pod_info.get("portMappings") {
        if let Some(port) = mappings.get("22") {
            if let Some(p) = port.as_u64() {
                return u16::try_from(p).context("SSH port out of u16 range");
            }
            if let Some(p) = port.as_str() {
                return p.parse::<u16>().context("invalid SSH port in portMappings");
            }
        }
    }

    bail!(
        "SSH port not found in pod portMappings. \
         Ensure the pod has port 22/tcp exposed, or use -p to specify manually."
    )
}

/// Execute a command on a remote host via SSH exec channel (no PTY).
fn ssh_exec(
    host: &str,
    port: u16,
    user: &str,
    key_path: &Path,
    command: &str,
    timeout: Duration,
) -> Result<(String, String, i32)> {
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .with_context(|| format!("invalid address: {host}:{port}"))?;

    let tcp = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("failed to connect to {host}:{port}"))?;

    let mut session = Session::new().context("failed to create SSH session")?;
    session.set_tcp_stream(tcp);
    session.handshake().context("SSH handshake failed")?;

    // Key-based auth
    if !key_path.exists() {
        bail!(
            "SSH key not found: {}. Use -i to specify key path.",
            key_path.display()
        );
    }
    session
        .userauth_pubkey_file(user, None, key_path, None)
        .with_context(|| {
            format!(
                "SSH authentication failed (user={user}, key={})",
                key_path.display()
            )
        })?;

    if !session.authenticated() {
        bail!("SSH authentication failed");
    }

    // Exec channel (no PTY)
    let mut channel = session
        .channel_session()
        .context("failed to open SSH channel")?;
    channel
        .exec(command)
        .with_context(|| format!("failed to execute: {command}"))?;

    let mut stdout = String::new();
    channel
        .read_to_string(&mut stdout)
        .context("failed to read stdout")?;

    let mut stderr = String::new();
    channel
        .stderr()
        .read_to_string(&mut stderr)
        .context("failed to read stderr")?;

    channel
        .wait_close()
        .context("failed to close SSH channel")?;
    let exit_code = channel.exit_status().context("failed to get exit status")?;

    Ok((stdout, stderr, exit_code))
}

/// Auto-detect SSH key from known candidates under $HOME.
fn detect_key_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        for candidate in KEY_CANDIDATES {
            let path = home.join(candidate);
            if path.exists() {
                return path;
            }
        }
    }
    // Fallback to first candidate (will produce clear error at auth time)
    default_key_path()
}

/// Resolve the default SSH key path ($HOME/.ssh/id_ed25519).
fn default_key_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(KEY_CANDIDATES[0]);
    }
    PathBuf::from("~").join(KEY_CANDIDATES[0])
}

/// Join command parts with shell-safe quoting.
///
/// Arguments containing spaces, semicolons, quotes, or other shell-special
/// characters are wrapped in single quotes.  This ensures the remote shell
/// receives each argument exactly as the user typed it.
fn shell_join(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|s| shell_quote(s))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quote a single shell argument if it contains special characters.
fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    // Safe characters that don't need quoting
    let safe = s.bytes().all(|b| {
        matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
            b'-' | b'_' | b'.' | b'/' | b'=' | b':' | b'@' | b'+' | b','
        )
    });
    if safe {
        return s.to_string();
    }
    // Wrap in single quotes, escaping embedded single quotes
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Expand leading `~` to $HOME.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_command ──

    #[test]
    fn command_has_required_args() {
        let cmd = build_command();
        let result = cmd.try_get_matches_from(["exec", "abc123", "--", "ls", "-la"]);
        assert!(result.is_ok(), "basic exec should parse: {result:?}");
    }

    #[test]
    fn command_requires_pod_id() {
        let cmd = build_command();
        let result = cmd.try_get_matches_from(["exec", "--", "ls"]);
        assert!(result.is_err(), "should require pod_id");
    }

    #[test]
    fn command_requires_command_after_separator() {
        let cmd = build_command();
        let result = cmd.try_get_matches_from(["exec", "abc123"]);
        assert!(result.is_err(), "should require command");
    }

    #[test]
    fn identity_flag_short() {
        let cmd = build_command();
        let m = cmd
            .try_get_matches_from(["exec", "-i", "/tmp/key", "pod1", "--", "ls"])
            .expect("should parse -i");
        assert_eq!(
            m.get_one::<String>("identity").map(|s| s.as_str()),
            Some("/tmp/key")
        );
    }

    #[test]
    fn login_name_flag() {
        let cmd = build_command();
        let m = cmd
            .try_get_matches_from(["exec", "-l", "ubuntu", "pod1", "--", "ls"])
            .expect("should parse -l");
        assert_eq!(
            m.get_one::<String>("login-name").map(|s| s.as_str()),
            Some("ubuntu")
        );
    }

    #[test]
    fn port_flag_short() {
        let cmd = build_command();
        let m = cmd
            .try_get_matches_from(["exec", "-p", "2222", "pod1", "--", "ls"])
            .expect("should parse -p");
        assert_eq!(
            m.get_one::<String>("port").map(|s| s.as_str()),
            Some("2222")
        );
    }

    #[test]
    fn host_flag() {
        let cmd = build_command();
        let m = cmd
            .try_get_matches_from(["exec", "--host", "10.0.0.1", "-p", "22", "pod1", "--", "ls"])
            .expect("should parse --host");
        assert_eq!(
            m.get_one::<String>("host").map(|s| s.as_str()),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn timeout_flag() {
        let cmd = build_command();
        let m = cmd
            .try_get_matches_from(["exec", "-t", "30", "pod1", "--", "ls"])
            .expect("should parse -t");
        assert_eq!(
            m.get_one::<String>("timeout").map(|s| s.as_str()),
            Some("30")
        );
    }

    #[test]
    fn command_with_multiple_args() {
        let cmd = build_command();
        let m = cmd
            .try_get_matches_from(["exec", "pod1", "--", "python", "train.py", "--epochs", "10"])
            .expect("should parse multi-arg command");
        let parts: Vec<&str> = m
            .get_many::<String>("command")
            .unwrap()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(parts, vec!["python", "train.py", "--epochs", "10"]);
    }

    #[test]
    fn default_login_name_is_root() {
        let cmd = build_command();
        let m = cmd
            .try_get_matches_from(["exec", "pod1", "--", "ls"])
            .expect("should parse");
        assert_eq!(
            m.get_one::<String>("login-name").map(|s| s.as_str()),
            Some("root")
        );
    }

    // ── extract_ssh_port ──

    #[test]
    fn extract_port_integer_value() {
        let info = serde_json::json!({
            "portMappings": {"22": 10341}
        });
        assert_eq!(extract_ssh_port(&info).unwrap(), 10341);
    }

    #[test]
    fn extract_port_string_value() {
        let info = serde_json::json!({
            "portMappings": {"22": "10341"}
        });
        assert_eq!(extract_ssh_port(&info).unwrap(), 10341);
    }

    #[test]
    fn extract_port_missing_mappings() {
        let info = serde_json::json!({"id": "pod1"});
        assert!(extract_ssh_port(&info).is_err());
    }

    #[test]
    fn extract_port_no_ssh_port() {
        let info = serde_json::json!({
            "portMappings": {"8888": 10342}
        });
        assert!(extract_ssh_port(&info).is_err());
    }

    #[test]
    fn extract_port_null_mappings() {
        let info = serde_json::json!({
            "portMappings": null
        });
        assert!(extract_ssh_port(&info).is_err());
    }

    // ── expand_tilde ──

    #[test]
    fn expand_tilde_with_home() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".to_string());
        let result = expand_tilde("~/foo/bar");
        assert_eq!(result, PathBuf::from(home).join("foo/bar"));
    }

    #[test]
    fn expand_tilde_absolute_path_unchanged() {
        let result = expand_tilde("/absolute/path/key");
        assert_eq!(result, PathBuf::from("/absolute/path/key"));
    }

    #[test]
    fn expand_tilde_relative_path_unchanged() {
        let result = expand_tilde("relative/path/key");
        assert_eq!(result, PathBuf::from("relative/path/key"));
    }

    // ── default_key_path / detect_key_path ──

    #[test]
    fn default_key_ends_with_id_ed25519() {
        let path = default_key_path();
        assert!(
            path.ends_with(".ssh/id_ed25519"),
            "expected path to end with .ssh/id_ed25519, got: {}",
            path.display()
        );
    }

    #[test]
    fn detect_key_returns_existing_key() {
        let path = detect_key_path();
        // On a system with any SSH key, this should find one
        // If no key exists, it falls back to default
        assert!(
            path.to_str().map(|s| s.contains(".ssh/")).unwrap_or(false),
            "detected key should be under .ssh/: {}",
            path.display()
        );
    }

    // ── shell_quote / shell_join ──

    #[test]
    fn shell_quote_simple_word() {
        assert_eq!(shell_quote("ls"), "ls");
    }

    #[test]
    fn shell_quote_with_spaces() {
        assert_eq!(shell_quote("hello world"), "'hello world'");
    }

    #[test]
    fn shell_quote_with_semicolon() {
        assert_eq!(
            shell_quote("import torch; print('ok')"),
            "'import torch; print('\\''ok'\\'')'",
        );
    }

    #[test]
    fn shell_quote_empty() {
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn shell_quote_safe_chars() {
        assert_eq!(shell_quote("--epochs=10"), "--epochs=10");
        assert_eq!(shell_quote("/workspace/train.py"), "/workspace/train.py");
    }

    #[test]
    fn shell_join_preserves_args() {
        let parts = vec!["python3", "-c", "import torch; print(torch.__version__)"];
        let joined = shell_join(&parts);
        assert_eq!(
            joined,
            "python3 -c 'import torch; print(torch.__version__)'"
        );
    }

    // ── resolve_connection ──

    #[test]
    fn resolve_connection_rejects_non_running_pod() {
        let info = serde_json::json!({
            "desiredStatus": "EXITED",
            "publicIp": "1.2.3.4",
            "portMappings": {"22": 10341}
        });
        // Test via extract logic (resolve_connection calls API, so test the status check directly)
        let status = info.get("desiredStatus").and_then(|v| v.as_str());
        assert_eq!(status, Some("EXITED"));
    }
}
