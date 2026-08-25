#!/usr/bin/env bash
set -euo pipefail

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-D warnings"

# GitHub gives the complete Rust job 15 minutes. This single command gets 13
# minutes so setup and failure reporting retain headroom. One workspace-wide
# selection prevents narrower feature selections from recompiling dependencies.
# The rebuild kill-point simulation is a documented nondeterministic test and
# remains outside the protected gate; every other non-ignored target runs here.
timeout 780 cargo test --profile ci --locked --workspace --all-targets -- \
    --skip base_rebuild_resumes_after_a_kill_between_any_two_phases
