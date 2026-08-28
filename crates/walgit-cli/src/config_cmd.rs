//! `walgit config check|dump` — validate configuration or print its
//! credential-safe diagnostic projection. The dump is not a round-trippable
//! configuration file: secret values are omitted and replaced by configured
//! state where useful.

use std::sync::Arc;

use anyhow::Result;

use crate::ConfigAction;
use walgit_config::Config;

pub async fn run(action: ConfigAction, cfg: &Arc<Config>) -> Result<()> {
    match action {
        ConfigAction::Check { env_files, strict } => {
            let mut cfg: Config = (**cfg).clone();
            let mut vars: Vec<(String, String)> = Vec::new();
            for f in &env_files {
                let text = std::fs::read_to_string(f)
                    .map_err(|e| anyhow::anyhow!("reading {}: {e}", f.display()))?;
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some((k, v)) = line.split_once('=') {
                        vars.push((k.trim().to_string(), v.trim().trim_matches('"').to_string()));
                    }
                }
            }
            let ignored = cfg.apply_env_report(vars.into_iter())?;
            cfg.validate()?;
            walgit_server::auth::Authenticator::validate_static_tokens(&cfg)?;
            for (k, why) in &ignored {
                eprintln!("ignored {k}: {why}");
            }
            if ignored.is_empty() {
                println!("config OK");
            } else {
                println!(
                    "config OK ({} override(s) ignored — unknown in this build)",
                    ignored.len()
                );
                if strict {
                    std::process::exit(3);
                }
            }
            Ok(())
        }
        ConfigAction::Dump => {
            let toml = cfg.safe_view().to_toml_string()?;
            println!("{toml}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walgit_config::StaticToken;

    #[tokio::test]
    async fn check_rejects_static_tokens_that_server_startup_would_reject() {
        let mut cfg = Config::default();
        cfg.store.bucket = "check-bucket".into();
        cfg.server.auth.tokens = vec![
            StaticToken {
                principal: "first".into(),
                token: "duplicate-check-token".into(),
                token_env: None,
                write: true,
            },
            StaticToken {
                principal: "second".into(),
                token: "duplicate-check-token".into(),
                token_env: None,
                write: false,
            },
        ];

        let err = run(
            ConfigAction::Check {
                env_files: Vec::new(),
                strict: false,
            },
            &Arc::new(cfg),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("duplicate"), "{err}");
        assert!(
            !err.contains("duplicate-check-token"),
            "config check leaked token material: {err}"
        );
    }
}
