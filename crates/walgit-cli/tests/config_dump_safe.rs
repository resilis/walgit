#[test]
fn config_dump_redacts_valid_url_paths() {
    let dir = tempfile::tempdir().expect("temporary config directory");
    let config = dir.path().join("walgit.toml");
    std::fs::write(
        &config,
        r#"
[store]
bucket = "config-dump"

[server]
public_url = "https://public.example:8443/public-cli-capability-sentinel"
cors_origins = ["https://cors.example:9444"]

[server.auth]
issuer = "https://issuer.example:9443/issuer-cli-capability-sentinel"

[store.gcs]
endpoint = "https://gcs.example:4443/gcs-cli-capability-sentinel"

[store.s3]
endpoint = "https://s3.example:5443/s3-cli-capability-sentinel"

[wal]
push_broker_url = "https://broker.example:6443/broker-cli-capability-sentinel"

[upstream]
git = "https://git.example:7443/git-cli-capability-sentinel"
lfs = "https://lfs.example:8444/lfs-cli-capability-sentinel"

[events]
webhook_url = "https://hooks.example/webhook-cli-capability-sentinel?token=webhook-query-sentinel"
"#,
    )
    .expect("write test config");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_walgit"))
        .env_clear()
        .args(["--config", config.to_str().unwrap(), "config", "dump"])
        .output()
        .expect("run production CLI config dump");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = String::from_utf8(output.stdout).expect("UTF-8 config dump");
    let table: toml::Table = toml::from_str(&text).expect("TOML config dump");
    for (actual, expected) in [
        (
            table["server"]["public_url"].as_str(),
            "https://public.example:8443/_path_redacted_",
        ),
        (
            table["server"]["auth"]["issuer"].as_str(),
            "https://issuer.example:9443/_path_redacted_",
        ),
        (
            table["store"]["gcs"]["endpoint"].as_str(),
            "https://gcs.example:4443/_path_redacted_",
        ),
        (
            table["store"]["s3"]["endpoint"].as_str(),
            "https://s3.example:5443/_path_redacted_",
        ),
        (
            table["wal"]["push_broker_url"].as_str(),
            "https://broker.example:6443/_path_redacted_",
        ),
        (
            table["upstream"]["git"].as_str(),
            "https://git.example:7443/_path_redacted_",
        ),
        (
            table["upstream"]["lfs"].as_str(),
            "https://lfs.example:8444/_path_redacted_",
        ),
    ] {
        assert_eq!(actual, Some(expected), "{text}");
    }
    assert_eq!(
        table["server"]["cors_origins"][0].as_str(),
        Some("https://cors.example:9444/")
    );
    assert_eq!(
        table["events"]["webhook_url_configured"].as_bool(),
        Some(true)
    );
    for sentinel in [
        "public-cli-capability-sentinel",
        "issuer-cli-capability-sentinel",
        "gcs-cli-capability-sentinel",
        "s3-cli-capability-sentinel",
        "broker-cli-capability-sentinel",
        "git-cli-capability-sentinel",
        "lfs-cli-capability-sentinel",
        "webhook-cli-capability-sentinel",
        "webhook-query-sentinel",
    ] {
        assert!(!text.contains(sentinel), "config dump leaked {sentinel}");
    }
}
