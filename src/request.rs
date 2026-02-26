//! Request execution and debugging (`--dry-run`, `--verbose`).
//!
//! Wraps upstream [`openapi_clap::PreparedRequest`] with [`ExecMode`] dispatch
//! for dry-run display, verbose logging, and normal execution.

use anyhow::Result;
use openapi_clap::clap::ArgMatches;
use openapi_clap::reqwest::blocking::Client;
use openapi_clap::{ApiOperation, Auth, PreparedRequest, ResolvedAuth};
use serde_json::Value;

/// Execution mode for HTTP requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    /// Send the request and return the response.
    Normal,
    /// Print the request that would be sent, then exit without sending.
    DryRun,
    /// Print request/response details to stderr, send normally.
    Verbose,
}

/// Build from an [`ApiOperation`] with upstream body resolution.
///
/// Chains [`PreparedRequest::from_operation`] + [`openapi_clap::build_body`]
/// (which supports `@file`/stdin via [`openapi_clap::resolve_json`]).
pub fn from_operation(
    base_url: &str,
    auth: &Auth<'_>,
    op: &ApiOperation,
    matches: &ArgMatches,
) -> Result<PreparedRequest> {
    let mut req = PreparedRequest::from_operation(base_url, auth, op, matches)?;
    if let Some(body) = openapi_clap::build_body(op, matches)? {
        req = req.body(body);
    }
    Ok(req)
}

/// Execute a prepared request in the given mode.
///
/// Returns `None` for dry-run (no response), `Some(value)` otherwise.
pub fn execute(client: &Client, req: &PreparedRequest, mode: ExecMode) -> Result<Option<Value>> {
    match mode {
        ExecMode::DryRun => {
            print_dry_run(req);
            Ok(None)
        }
        ExecMode::Verbose => {
            print_verbose_request(req);
            let resp = req.send(client)?;
            eprintln!("< {} ({:.0?})", resp.status, resp.elapsed);
            for (name, value) in resp.headers.iter() {
                eprintln!("< {}: {}", name, value.to_str().unwrap_or("<binary>"));
            }
            let value = resp.into_json()?;
            Ok(Some(value))
        }
        ExecMode::Normal => {
            let value = req.send(client)?.into_json()?;
            Ok(Some(value))
        }
    }
}

// ── display helpers ─────────────────────────────────────────────────

/// Full URL including query string (for display).
fn full_url(req: &PreparedRequest) -> String {
    if req.query_pairs.is_empty() {
        return req.url.clone();
    }
    let qs: Vec<String> = req
        .query_pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect();
    format!("{}?{}", req.url, qs.join("&"))
}

fn mask_auth(auth: &ResolvedAuth) -> Option<(String, String)> {
    match auth {
        ResolvedAuth::None => None,
        ResolvedAuth::Bearer(_) => Some(("Authorization".to_string(), "Bearer ***".to_string())),
        ResolvedAuth::Header { name, .. } => Some((name.clone(), "***".to_string())),
        ResolvedAuth::Basic { .. } => Some(("Authorization".to_string(), "Basic ***".to_string())),
        ResolvedAuth::Query { .. } => None, // shown in URL, not as header
        _ => None,                          // non_exhaustive future variants
    }
}

/// Print dry-run output to stdout.
fn print_dry_run(req: &PreparedRequest) {
    println!("{} {}", req.method, full_url(req));
    if let Some((name, value)) = mask_auth(&req.auth) {
        println!("{name}: {value}");
    }
    for (name, value) in &req.headers {
        println!("{name}: {value}");
    }
    if req.body.is_some() {
        println!("Content-Type: application/json");
    }
    if let Some(body) = &req.body {
        println!();
        println!("{}", serde_json::to_string_pretty(body).unwrap_or_default());
    }
}

/// Print verbose request details to stderr.
fn print_verbose_request(req: &PreparedRequest) {
    eprintln!("> {} {}", req.method, full_url(req));
    if let Some((name, value)) = mask_auth(&req.auth) {
        eprintln!("> {name}: {value}");
    }
    for (name, value) in &req.headers {
        eprintln!("> {name}: {value}");
    }
    if req.body.is_some() {
        eprintln!("> Content-Type: application/json");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_clap::reqwest::Method;

    // ── full_url ──────────────────────────────────────────────────

    #[test]
    fn full_url_without_query_params() {
        let req = PreparedRequest::new(Method::GET, "https://example.com/v1/pods");
        assert_eq!(full_url(&req), "https://example.com/v1/pods");
    }

    #[test]
    fn full_url_with_single_query_param() {
        let req =
            PreparedRequest::new(Method::GET, "https://example.com/v1/pods").query("limit", "10");
        assert_eq!(full_url(&req), "https://example.com/v1/pods?limit=10");
    }

    #[test]
    fn full_url_with_multiple_query_params() {
        let req = PreparedRequest::new(Method::GET, "https://example.com/v1/pods")
            .query("limit", "10")
            .query("offset", "20");
        assert_eq!(
            full_url(&req),
            "https://example.com/v1/pods?limit=10&offset=20"
        );
    }

    #[test]
    fn full_url_encodes_special_chars() {
        let req = PreparedRequest::new(Method::GET, "https://example.com/search")
            .query("q", "hello world");
        assert_eq!(full_url(&req), "https://example.com/search?q=hello%20world");
    }

    // ── mask_auth ─────────────────────────────────────────────────

    #[test]
    fn mask_auth_none() {
        assert!(mask_auth(&ResolvedAuth::None).is_none());
    }

    #[test]
    fn mask_auth_bearer() {
        let result = mask_auth(&ResolvedAuth::Bearer("secret-token".into()));
        assert_eq!(
            result,
            Some(("Authorization".to_string(), "Bearer ***".to_string()))
        );
    }

    #[test]
    fn mask_auth_header() {
        let result = mask_auth(&ResolvedAuth::Header {
            name: "X-API-Key".into(),
            value: "secret".into(),
        });
        assert_eq!(result, Some(("X-API-Key".to_string(), "***".to_string())));
    }

    #[test]
    fn mask_auth_basic() {
        let result = mask_auth(&ResolvedAuth::Basic {
            username: "user".into(),
            password: Some("pass".into()),
        });
        assert_eq!(
            result,
            Some(("Authorization".to_string(), "Basic ***".to_string()))
        );
    }

    #[test]
    fn mask_auth_query_returns_none() {
        let result = mask_auth(&ResolvedAuth::Query {
            name: "api_key".into(),
            value: "secret".into(),
        });
        assert!(result.is_none());
    }

    // ── ExecMode ──────────────────────────────────────────────────

    #[test]
    fn exec_mode_equality() {
        assert_eq!(ExecMode::DryRun, ExecMode::DryRun);
        assert_ne!(ExecMode::DryRun, ExecMode::Normal);
        assert_ne!(ExecMode::Normal, ExecMode::Verbose);
    }
}
