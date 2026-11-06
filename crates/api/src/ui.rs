//! Operator UI (SvelteKit single-page app, `ui/build`) embedded in the binary.
//! Debug build -> files read from disk -> `npm run build` seen without recompile.

use axum::body::Body;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../../ui/build"]
#[allow_missing = true]
struct Assets;

fn file(path: &str) -> Option<Response> {
    let asset = Assets::get(path)?;
    let cache = if path.starts_with("_app/immutable/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    Some(
        (
            [
                (header::CONTENT_TYPE, asset.metadata.mimetype().to_owned()),
                (header::CACHE_CONTROL, cache.to_owned()),
            ],
            Body::from(asset.data.into_owned()),
        )
            .into_response(),
    )
}

/// Static files. Fallback `index.html` for client-side routes.
pub(crate) async fn serve(uri: Uri) -> Response {
    let path = match uri.path().trim_start_matches('/') {
        "" => "index.html",
        // Browsers ask for /favicon.ico even with <link rel="icon">.
        "favicon.ico" => "favicon.svg",
        p => p,
    };
    // Unknown API path = API error, not a client-side route -> JSON 404, never the UI page.
    if path == "api" || path.starts_with("api/") {
        return crate::not_found("API path").into_response();
    }
    if let Some(r) = file(path) {
        return r;
    }
    // Missing asset -> real 404. Else -> client-side route.
    if path.starts_with("_app/") || path.rsplit('/').next().is_some_and(|f| f.contains('.')) {
        return StatusCode::NOT_FOUND.into_response();
    }
    file("index.html").unwrap_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "The web UI is not built. Run `npm run build` in ui/ (see CONTRIBUTING.md).",
        )
            .into_response()
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn unknown_api_paths_are_json_404s() {
        for path in ["/api", "/api/v1/no-such-endpoint", "/api/v2/devices"] {
            let resp = serve(path.parse().unwrap()).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
            let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
            assert!(
                ct.to_str().unwrap().starts_with("application/json"),
                "{path}"
            );
        }
    }
}
