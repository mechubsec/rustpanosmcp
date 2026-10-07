//! Pins the operator-visible text of every startup refusal.
//!
//! These messages are part of the operator contract: the setup guide quotes
//! them, and an operator who hits one has nothing else to search for. Nothing
//! pinned them before, which is how this binary came to print `Error:
//! AllowedOriginRequired` — the name of an enum variant — while the
//! documentation quoted a sentence naming the flag. See mecmcp#358.
//!
//! The assertions deliberately run the real binary rather than calling
//! `mecmcp_runtime::cli_validate::validate_or_exit` directly. The process
//! boundary keeps the operator-facing contract observable.

use std::io::Write;
use std::process::{Command, Output};

/// A tokens file that exists and is mode 0600, so the run reaches CLI
/// validation instead of failing on the token store first.
fn tokens_file() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create tokens file");
    file.write_all(b"{}").expect("write tokens file");
    file.flush().expect("flush tokens file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("chmod tokens file");
    }
    file
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rust-panosmcp"))
        .args(args)
        .output()
        .expect("spawn rust-panosmcp")
}

/// Asserts the refusal text reached stderr, and that the bare variant name did
/// not. The second half is the regression guard: `Debug`-formatting the enum
/// prints the variant, which is what this test exists to keep out.
fn assert_refusal(output: &Output, expected: &str, variant: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(expected),
        "expected stderr to contain {expected:?}, got:\n{stderr}"
    );
    assert!(
        !stderr.contains(variant),
        "stderr leaked the {variant:?} enum variant instead of its message:\n{stderr}"
    );
    assert!(
        !output.status.success(),
        "a refused CLI must exit non-zero, got {:?}",
        output.status
    );
}

#[test]
fn off_loopback_without_allowed_origin_names_the_flag() {
    let tokens = tokens_file();
    let output = run(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "30031",
        "--tokens-file",
        tokens.path().to_str().expect("tokens path is valid UTF-8"),
        "--allow-insecure-bind",
        "--allowed-host",
        "10.0.0.1:30031",
    ]);
    assert_refusal(
        &output,
        "non-loopback Streamable HTTP requires at least one --allowed-origin",
        "AllowedOriginRequired",
    );
}

#[test]
fn off_loopback_without_allowed_host_names_the_flag() {
    let tokens = tokens_file();
    let output = run(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "30031",
        "--tokens-file",
        tokens.path().to_str().expect("tokens path is valid UTF-8"),
        "--allow-insecure-bind",
    ]);
    assert_refusal(
        &output,
        "non-loopback Streamable HTTP requires at least one --allowed-host",
        "AllowedHostRequired",
    );
}

/// Auth, host, and origin rules are shared with mecmcp; these assertions pin
/// their behavior at the server process boundary.
#[test]
fn tokens_file_and_allow_no_auth_are_mutually_exclusive() {
    let tokens = tokens_file();
    let output = run(&[
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--tokens-file",
        tokens.path().to_str().expect("tokens path is valid UTF-8"),
        "--allow-no-auth",
    ]);
    assert_refusal(
        &output,
        "--tokens-file and --allow-no-auth are mutually exclusive",
        "AuthConflict",
    );
}

#[test]
fn bind_host_must_be_numeric() {
    let tokens = tokens_file();
    let output = run(&[
        "--transport",
        "streamable-http",
        "--host",
        "evil.example.com",
        "--tokens-file",
        tokens.path().to_str().expect("tokens path is valid UTF-8"),
        "--allow-insecure-bind",
        "--allowed-host",
        "evil.example.com:30031",
        "--allowed-origin",
        "https://evil.example.com",
    ]);
    assert_refusal(
        &output,
        "--host must be a numeric IPv4 or IPv6 address, got 'evil.example.com'",
        "NonNumericHost",
    );
}

#[test]
fn malformed_allowed_origin_is_refused() {
    let tokens = tokens_file();
    let output = run(&[
        "--transport",
        "streamable-http",
        "--host",
        "10.0.0.1",
        "--tokens-file",
        tokens.path().to_str().expect("tokens path is valid UTF-8"),
        "--allow-insecure-bind",
        "--allowed-host",
        "10.0.0.1:30031",
        "--allowed-origin",
        "not a url",
    ]);
    assert_refusal(
        &output,
        "invalid --allowed-origin URL 'not a url'",
        "InvalidAllowedOrigin",
    );
}
