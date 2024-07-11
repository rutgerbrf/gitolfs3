mod api;
mod authz;
mod config;
mod dlimit;
mod handler;

use api::RepositoryName;
use config::Config;
use dlimit::DownloadLimiter;

use axum::{
    extract::OriginalUri,
    http::{self, Uri},
    routing::{get, post},
    Router, ServiceExt,
};
use handler::{handle_batch, handle_obj_download, AppState};
use std::{process::ExitCode, sync::Arc};
use tokio::net::TcpListener;
use tower::Layer;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt::init();

    let conf = match Config::load() {
        Ok(conf) => conf,
        Err(e) => {
            println!("Error: {e}");
            return ExitCode::from(2);
        }
    };

    let dl_limiter = DownloadLimiter::new(conf.download_limit).await;
    let shared_state = Arc::new(AppState {
        s3_client: conf.s3_client,
        s3_bucket: conf.s3_bucket,
        authz_conf: conf.authz_conf,
        base_url: conf.base_url,
        dl_limiter,
    });
    let app = Router::new()
        .route("/batch", post(handle_batch))
        .route("/:oid0/:oid1/:oid", get(handle_obj_download))
        .with_state(shared_state);

    let middleware = axum::middleware::map_request(rewrite_url);
    let app_with_middleware = middleware.layer(app);

    let listener = match TcpListener::bind(conf.listen_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            println!("Failed to listen: {e}");
            return ExitCode::FAILURE;
        }
    };

    match axum::serve(listener, app_with_middleware.into_make_service()).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            println!("Error serving: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn rewrite_url<B>(mut req: http::Request<B>) -> Result<http::Request<B>, http::StatusCode> {
    let uri = req.uri();
    let original_uri = OriginalUri(uri.clone());

    let Some(path_and_query) = uri.path_and_query() else {
        // L @ no path & query
        return Err(http::StatusCode::BAD_REQUEST);
    };
    let Some((repo, path)) = path_and_query.path().split_once("/info/lfs/objects") else {
        return Err(http::StatusCode::NOT_FOUND);
    };
    let repo = repo
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string();
    if !path.starts_with('/') || !repo.ends_with(".git") {
        return Err(http::StatusCode::NOT_FOUND);
    }

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = match path_and_query.query() {
        None => path.try_into().ok(),
        Some(q) => format!("{path}?{q}").try_into().ok(),
    };
    let Ok(new_uri) = Uri::from_parts(parts) else {
        return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
    };

    *req.uri_mut() = new_uri;
    req.extensions_mut().insert(original_uri);
    req.extensions_mut().insert(RepositoryName(repo));

    Ok(req)
}
