#[test]
fn config_check_does_not_echo_malformed_webhook_source() {
    const SENTINEL: &str = "cli-malformed-webhook-path-sentinel";

    let dir = tempfile::tempdir().expect("temporary config directory");
    let config = dir.path().join("walgit.toml");
    std::fs::write(
        &config,
        format!("[events]\nwebhook_url = \"https://hooks.example/{SENTINEL}\n"),
    )
    .expect("write malformed test config");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_walgit"))
        .env_clear()
        .args(["--config", config.to_str().unwrap(), "config", "check"])
        .output()
        .expect("run production CLI config check");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("config: invalid TOML"), "{stderr}");
    assert!(
        !stderr.contains(SENTINEL),
        "config check leaked source: {stderr}"
    );
    assert!(!stderr.contains("webhook_url ="), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}
