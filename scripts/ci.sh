#!/usr/bin/env bash
set -euo pipefail

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-D warnings"

# The complete remote quality job has a 15-minute hard cap. Compilation gets
# 12 minutes and each execution selection gets 5 minutes, but the job cap is
# authoritative. All commands share this non-incremental CI fingerprint.
timeout 720 cargo test --profile ci --locked --workspace --all-targets --no-run
timeout 300 cargo test --profile ci --locked --workspace --lib --bins
timeout 300 cargo test --profile ci --locked -p walgit-store -p walgit-git -p walgit-wal -p walgit-bundle --tests
timeout 300 cargo test --profile ci --locked -p walgit-server --test web_api --test web_ui --test api_v1 --test static_http --test maintain --test routing_prefix --test lfs_upstream --test drain
timeout 300 cargo test --profile ci --locked -p walgit-server --test e2e
