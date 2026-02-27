use anyhow::{Context, Result};
use openapi_clap::clap::{Arg, ArgMatches, Command};
use openapi_clap::reqwest::blocking::Client;

use crate::ssh;

/// Build the `exec` subcommand (SSH-compatible options where applicable).
pub fn build_command() -> Command {
    ssh::add_ssh_args(
        Command::new("exec")
            .about("Execute a command on a running pod via SSH (non-interactive)")
            .long_about(
                "Execute a command on a running pod via SSH exec channel (no PTY required).\n\n\
                 Connection is made via Direct TCP (public IP + mapped port), which is \
                 auto-detected from the RunPod API. Use --host and -p to override.",
            ),
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
    let target = ssh::resolve_target(client, api_key, base_url, matches)?;

    let command_parts: Vec<&str> = matches
        .get_many::<String>("command")
        .context("command is required")?
        .map(|s| s.as_str())
        .collect();
    let command = ssh::shell_join(&command_parts);

    // Connect and execute
    let (stdout, stderr, exit_code) = ssh::ssh_exec(&target, &command)?;

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
}
