//! Prometheus metrics exporter. Installs a recorder up front (once per process)
//! and exposes the rendered scrape via `/metrics`.

use std::sync::{Arc, OnceLock};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::PrometheusHandle;

use crate::AppState;

static HANDLE: OnceLock<Arc<PrometheusHandle>> = OnceLock::new();

/// Install the Prometheus recorder once per process and return a shared handle.
/// Safe to call repeatedly (subsequent calls return the same handle).
pub fn install() -> anyhow::Result<Arc<PrometheusHandle>> {
    if let Some(h) = HANDLE.get() {
        return Ok(h.clone());
    }
    use metrics_exporter_prometheus::PrometheusBuilder;
    let rec = PrometheusBuilder::new().build_recorder();
    let handle = Arc::new(rec.handle());
    // set_global_recorder fails if already set; ignore that race — the handle is
    // what we actually need.
    let _ = metrics::set_global_recorder(Box::new(rec));
    // Two callers may race here; OnceLock keeps the first, both handles are
    // identical (same recorder), so dropping the second is harmless.
    let _ = HANDLE.set(handle.clone());
    Ok(HANDLE.get().unwrap_or(&handle).clone())
}

/// `GET /metrics`
pub async fn metrics_route(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, crate::error::ApiError> {
    st.auth.require_operator(&headers).await.map_err(auth_err)?;
    let body = st.metrics_handle.render();
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response())
}

fn auth_err(error: crate::auth::AuthError) -> crate::error::ApiError {
    match error {
        crate::auth::AuthError::Invalid | crate::auth::AuthError::Unauthorized => {
            crate::error::ApiError::Unauthorized
        }
        crate::auth::AuthError::Forbidden | crate::auth::AuthError::TenantForbidden => {
            crate::error::ApiError::Forbidden
        }
        crate::auth::AuthError::TenantNotFound => {
            crate::error::ApiError::NotFound("repository".into())
        }
        crate::auth::AuthError::Unavailable => {
            crate::error::ApiError::ServiceUnavailable("auth provider unavailable".into())
        }
    }
}
