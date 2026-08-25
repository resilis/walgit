#[cfg(unix)]
#[test]
fn config_check_routes_selected_non_unicode_token_env_to_typed_auth_error() {
    use std::os::unix::ffi::OsStringExt;

    let dir = tempfile::tempdir().expect("temporary config directory");
    let config = dir.path().join("walgit.toml");
    std::fs::write(
        &config,
        r#"
[store]
bucket = "config-check"

[server.auth]
mode = "token"
issuer = ""

[[server.auth.tokens]]
principal = "robot"
token = "literal-fallback-must-not-be-used"
token_env = "SELECTED_TOKEN_ENV"
"#,
    )
    .expect("write test config");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_walgit"))
        .env_clear()
        .env(
            "SELECTED_TOKEN_ENV",
            std::ffi::OsString::from_vec(b"selected-token-value-sentinel-\xff".to_vec()),
        )
        .args(["--config", config.to_str().unwrap(), "config", "check"])
        .output()
        .expect("run production CLI config check");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("server.auth.tokens[0]"), "{stderr}");
    assert!(stderr.contains("SELECTED_TOKEN_ENV"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(
        !stderr.contains("literal-fallback-must-not-be-used")
            && !stderr.contains("selected-token-value-sentinel"),
        "config check leaked token material: {stderr}"
    );
}
