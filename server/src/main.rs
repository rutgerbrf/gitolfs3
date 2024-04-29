use aws_sdk_s3::{error::SdkError, operation::head_object::HeadObjectOutput};
use axum::{
    async_trait,
    extract::{rejection, FromRequest, FromRequestParts, OriginalUri, Path, Request, State},
    http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router, ServiceExt,
};
use base64::prelude::*;
use chrono::{DateTime, Utc};
use serde::{
    de::{self, DeserializeOwned},
    Deserialize, Serialize,
};
use std::{
    collections::{HashMap, HashSet},
    process::ExitCode,
    sync::Arc,
};
use tokio::io::AsyncWriteExt;
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
    let dl_limiter = Arc::new(tokio::sync::Mutex::new(dl_limiter));

    let resetter_dl_limiter = dl_limiter.clone();
    tokio::spawn(async move {
        loop {
            println!("Resetting download counter in one hour");
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            println!("Resetting download counter");
            resetter_dl_limiter.lock().await.reset().await;
        }
    });

    let shared_state = Arc::new(AppState {
        s3_client: conf.s3_client,
        s3_bucket: conf.s3_bucket,
        authz_conf: conf.authz_conf,
        base_url: conf.base_url,
        dl_limiter,
    });
    let app = Router::new()
        .route("/batch", post(batch))
        .route("/:oid0/:oid1/:oid", get(obj_download))
        .with_state(shared_state);

    let middleware = axum::middleware::map_request(rewrite_url);
    let app_with_middleware = middleware.layer(app);

    let listener = match tokio::net::TcpListener::bind(conf.listen_addr).await {
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

#[derive(Clone)]
struct RepositoryName(String);

struct RepositoryNameRejection;

impl IntoResponse for RepositoryNameRejection {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, "Missing repository name").into_response()
    }
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for RepositoryName {
    type Rejection = RepositoryNameRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Ok(Extension(repo_name)) = Extension::<Self>::from_request_parts(parts, state).await
        else {
            return Err(RepositoryNameRejection);
        };
        Ok(repo_name)
    }
}

async fn rewrite_url<B>(
    mut req: axum::http::Request<B>,
) -> Result<axum::http::Request<B>, StatusCode> {
    let uri = req.uri();
    let original_uri = OriginalUri(uri.clone());

    let Some(path_and_query) = uri.path_and_query() else {
        // L @ no path & query
        return Err(StatusCode::BAD_REQUEST);
    };
    let Some((repo, path)) = path_and_query.path().split_once("/info/lfs/objects") else {
        return Err(StatusCode::NOT_FOUND);
    };
    let repo = repo
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string();
    if !path.starts_with('/') || !repo.ends_with(".git") {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = match path_and_query.query() {
        None => path.try_into().ok(),
        Some(q) => format!("{path}?{q}").try_into().ok(),
    };
    let Ok(new_uri) = Uri::from_parts(parts) else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    *req.uri_mut() = new_uri;
    req.extensions_mut().insert(original_uri);
    req.extensions_mut().insert(RepositoryName(repo));

    Ok(req)
}

struct AppState {
    s3_client: aws_sdk_s3::Client,
    s3_bucket: String,
    authz_conf: AuthorizationConfig,
    // Should not end with a slash.
    base_url: String,
    dl_limiter: Arc<tokio::sync::Mutex<DownloadLimiter>>,
}

struct Env {
    s3_access_key_id: String,
    s3_secret_access_key: String,
    s3_bucket: String,
    s3_region: String,
    s3_endpoint: String,
    base_url: String,
    key_path: String,
    listen_host: String,
    listen_port: String,
    download_limit: String,
    trusted_forwarded_hosts: String,
}

fn require_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .map_err(|_| format!("environment variable {name} should be defined and valid"))
}

impl Env {
    fn load() -> Result<Env, String> {
        Ok(Env {
            s3_secret_access_key: require_env("GITOLFS3_S3_SECRET_ACCESS_KEY_FILE")?,
            s3_access_key_id: require_env("GITOLFS3_S3_ACCESS_KEY_ID_FILE")?,
            s3_region: require_env("GITOLFS3_S3_REGION")?,
            s3_endpoint: require_env("GITOLFS3_S3_ENDPOINT")?,
            s3_bucket: require_env("GITOLFS3_S3_BUCKET")?,
            base_url: require_env("GITOLFS3_BASE_URL")?,
            key_path: require_env("GITOLFS3_KEY_PATH")?,
            listen_host: require_env("GITOLFS3_LISTEN_HOST")?,
            listen_port: require_env("GITOLFS3_LISTEN_PORT")?,
            download_limit: require_env("GITOLFS3_DOWNLOAD_LIMIT")?,
            trusted_forwarded_hosts: std::env::var("GITOLFS3_TRUSTED_FORWARDED_HOSTS")
                .unwrap_or_default(),
        })
    }
}

fn get_s3_client(env: &Env) -> Result<aws_sdk_s3::Client, std::io::Error> {
    let access_key_id = std::fs::read_to_string(&env.s3_access_key_id)?;
    let secret_access_key = std::fs::read_to_string(&env.s3_secret_access_key)?;

    let credentials = aws_sdk_s3::config::Credentials::new(
        access_key_id,
        secret_access_key,
        None,
        None,
        "gitolfs3-env",
    );
    let config = aws_config::SdkConfig::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(env.s3_region.clone()))
        .endpoint_url(&env.s3_endpoint)
        .credentials_provider(aws_sdk_s3::config::SharedCredentialsProvider::new(
            credentials,
        ))
        .build();
    Ok(aws_sdk_s3::Client::new(&config))
}

struct Config {
    listen_addr: (String, u16),
    base_url: String,
    authz_conf: AuthorizationConfig,
    s3_client: aws_sdk_s3::Client,
    s3_bucket: String,
    download_limit: u64,
}

impl Config {
    fn load() -> Result<Self, String> {
        let env = match Env::load() {
            Ok(env) => env,
            Err(e) => return Err(format!("failed to load configuration: {e}")),
        };

        let s3_client = match get_s3_client(&env) {
            Ok(s3_client) => s3_client,
            Err(e) => return Err(format!("failed to create S3 client: {e}")),
        };
        let key = match common::load_key(&env.key_path) {
            Ok(key) => key,
            Err(e) => return Err(format!("failed to load Gitolfs3 key: {e}")),
        };

        let trusted_forwarded_hosts: HashSet<String> = env
            .trusted_forwarded_hosts
            .split(',')
            .map(|s| s.to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        let base_url = env.base_url.trim_end_matches('/').to_string();

        let Ok(listen_port): Result<u16, _> = env.listen_port.parse() else {
            return Err("configured GITOLFS3_LISTEN_PORT is invalid".to_string());
        };
        let Ok(download_limit): Result<u64, _> = env.download_limit.parse() else {
            return Err("configured GITOLFS3_DOWNLOAD_LIMIT is invalid".to_string());
        };

        Ok(Self {
            listen_addr: (env.listen_host, listen_port),
            base_url,
            authz_conf: AuthorizationConfig {
                key,
                trusted_forwarded_hosts,
            },
            s3_client,
            s3_bucket: env.s3_bucket,
            download_limit,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
enum TransferAdapter {
    #[serde(rename = "basic")]
    Basic,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
enum HashAlgo {
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(other)]
    Unknown,
}

impl Default for HashAlgo {
    fn default() -> Self {
        Self::Sha256
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
struct BatchRequestObject {
    oid: common::Oid,
    size: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BatchRef {
    name: String,
}

fn default_transfers() -> Vec<TransferAdapter> {
    vec![TransferAdapter::Basic]
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
struct BatchRequest {
    operation: common::Operation,
    #[serde(default = "default_transfers")]
    transfers: Vec<TransferAdapter>,
    objects: Vec<BatchRequestObject>,
    #[serde(default)]
    hash_algo: HashAlgo,
}

#[derive(Debug, Clone)]
struct GitLfsJson<T>(Json<T>);

const LFS_MIME: &str = "application/vnd.git-lfs+json";

enum GitLfsJsonRejection {
    Json(rejection::JsonRejection),
    MissingGitLfsJsonContentType,
}

impl IntoResponse for GitLfsJsonRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Json(rej) => rej.into_response(),
            Self::MissingGitLfsJsonContentType => make_error_resp(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &format!("Expected request with `Content-Type: {LFS_MIME}`"),
            )
            .into_response(),
        }
    }
}

fn is_git_lfs_json_mimetype(mimetype: &str) -> bool {
    let Ok(mime) = mimetype.parse::<mime::Mime>() else {
        return false;
    };
    if mime.type_() != mime::APPLICATION
        || mime.subtype() != "vnd.git-lfs"
        || mime.suffix() != Some(mime::JSON)
    {
        return false;
    }
    match mime.get_param(mime::CHARSET) {
        Some(mime::UTF_8) | None => true,
        Some(_) => false,
    }
}

fn has_git_lfs_json_content_type(req: &Request) -> bool {
    let Some(content_type) = req.headers().get(header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(content_type) = content_type.to_str() else {
        return false;
    };
    is_git_lfs_json_mimetype(content_type)
}

#[async_trait]
impl<T, S> FromRequest<S> for GitLfsJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = GitLfsJsonRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !has_git_lfs_json_content_type(&req) {
            return Err(GitLfsJsonRejection::MissingGitLfsJsonContentType);
        }
        Json::<T>::from_request(req, state)
            .await
            .map(GitLfsJson)
            .map_err(GitLfsJsonRejection::Json)
    }
}

impl<T: Serialize> IntoResponse for GitLfsJson<T> {
    fn into_response(self) -> Response {
        let GitLfsJson(json) = self;
        let mut resp = json.into_response();
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.git-lfs+json; charset=utf-8"),
        );
        resp
    }
}

#[derive(Debug, Serialize)]
struct GitLfsErrorData<'a> {
    message: &'a str,
}

type GitLfsErrorResponse<'a> = (StatusCode, GitLfsJson<GitLfsErrorData<'a>>);

const fn make_error_resp(code: StatusCode, message: &str) -> GitLfsErrorResponse {
    (code, GitLfsJson(Json(GitLfsErrorData { message })))
}

#[derive(Debug, Serialize, Clone)]
struct BatchResponseObjectAction {
    href: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    header: HashMap<String, String>,
    expires_at: DateTime<Utc>,
}

#[derive(Default, Debug, Serialize, Clone)]
struct BatchResponseObjectActions {
    #[serde(skip_serializing_if = "Option::is_none")]
    upload: Option<BatchResponseObjectAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<BatchResponseObjectAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify: Option<BatchResponseObjectAction>,
}

#[derive(Debug, Clone, Serialize)]
struct BatchResponseObjectError {
    code: u16,
    message: String,
}

#[derive(Debug, Serialize, Clone)]
struct BatchResponseObject {
    oid: common::Oid,
    size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    authenticated: Option<bool>,
    actions: BatchResponseObjectActions,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<BatchResponseObjectError>,
}

impl BatchResponseObject {
    fn error(obj: &BatchRequestObject, code: StatusCode, message: String) -> BatchResponseObject {
        BatchResponseObject {
            oid: obj.oid,
            size: obj.size,
            authenticated: None,
            actions: Default::default(),
            error: Some(BatchResponseObjectError {
                code: code.as_u16(),
                message,
            }),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct BatchResponse {
    transfer: TransferAdapter,
    objects: Vec<BatchResponseObject>,
    hash_algo: HashAlgo,
}

fn validate_checksum(oid: common::Oid, obj: &HeadObjectOutput) -> bool {
    if let Some(checksum) = obj.checksum_sha256() {
        if let Ok(checksum) = BASE64_STANDARD.decode(checksum) {
            if let Ok(checksum32b) = TryInto::<[u8; 32]>::try_into(checksum) {
                return common::Oid::from(checksum32b) == oid;
            }
        }
    }
    true
}

fn validate_size(expected: i64, obj: &HeadObjectOutput) -> bool {
    if let Some(length) = obj.content_length() {
        return length == expected;
    }
    true
}

async fn handle_upload_object(
    state: &AppState,
    repo: &str,
    obj: &BatchRequestObject,
) -> Option<BatchResponseObject> {
    let (oid0, oid1) = (common::HexByte(obj.oid[0]), common::HexByte(obj.oid[1]));
    let full_path = format!("{repo}/lfs/objects/{}/{}/{}", oid0, oid1, obj.oid);

    match state
        .s3_client
        .head_object()
        .bucket(&state.s3_bucket)
        .key(full_path.clone())
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
    {
        Ok(result) => {
            if validate_size(obj.size, &result) && validate_checksum(obj.oid, &result) {
                return None;
            }
        }
        Err(SdkError::ServiceError(e)) if e.err().is_not_found() => {}
        Err(e) => {
            println!("Failed to HeadObject (repo {repo}, OID {}): {e}", obj.oid);
            return Some(BatchResponseObject::error(
                obj,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query object information".to_string(),
            ));
        }
    };

    let expires_in = std::time::Duration::from_secs(5 * 60);
    let expires_at = Utc::now() + expires_in;

    let Ok(config) = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in) else {
        return Some(BatchResponseObject::error(
            obj,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate upload URL".to_string(),
        ));
    };
    let Ok(presigned) = state
        .s3_client
        .put_object()
        .bucket(&state.s3_bucket)
        .key(full_path)
        .checksum_sha256(obj.oid.to_string())
        .content_length(obj.size)
        .presigned(config)
        .await
    else {
        return Some(BatchResponseObject::error(
            obj,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate upload URL".to_string(),
        ));
    };
    Some(BatchResponseObject {
        oid: obj.oid,
        size: obj.size,
        authenticated: Some(true),
        actions: BatchResponseObjectActions {
            upload: Some(BatchResponseObjectAction {
                header: presigned
                    .headers()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
                expires_at,
                href: presigned.uri().to_string(),
            }),
            ..Default::default()
        },
        error: None,
    })
}

async fn handle_download_object(
    state: &AppState,
    repo: &str,
    obj: &BatchRequestObject,
    trusted: bool,
) -> BatchResponseObject {
    let (oid0, oid1) = (common::HexByte(obj.oid[0]), common::HexByte(obj.oid[1]));
    let full_path = format!("{repo}/lfs/objects/{}/{}/{}", oid0, oid1, obj.oid);

    let result = match state
        .s3_client
        .head_object()
        .bucket(&state.s3_bucket)
        .key(&full_path)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
    {
        Ok(result) => result,
        Err(e) => {
            println!("Failed to HeadObject (repo {repo}, OID {}): {e}", obj.oid);
            return BatchResponseObject::error(
                obj,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query object information".to_string(),
            );
        }
    };

    // Scaleway actually doesn't provide SHA256 suport, but maybe in the future :)
    if !validate_checksum(obj.oid, &result) {
        return BatchResponseObject::error(
            obj,
            StatusCode::UNPROCESSABLE_ENTITY,
            "Object corrupted".to_string(),
        );
    }
    if !validate_size(obj.size, &result) {
        return BatchResponseObject::error(
            obj,
            StatusCode::UNPROCESSABLE_ENTITY,
            "Incorrect size specified (or object corrupted)".to_string(),
        );
    }

    let expires_in = std::time::Duration::from_secs(5 * 60);
    let expires_at = Utc::now() + expires_in;

    if trusted {
        let Ok(config) = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in) else {
            return BatchResponseObject::error(
                obj,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate upload URL".to_string(),
            );
        };
        let Ok(presigned) = state
            .s3_client
            .get_object()
            .bucket(&state.s3_bucket)
            .key(full_path)
            .presigned(config)
            .await
        else {
            return BatchResponseObject::error(
                obj,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate upload URL".to_string(),
            );
        };
        return BatchResponseObject {
            oid: obj.oid,
            size: obj.size,
            authenticated: Some(true),
            actions: BatchResponseObjectActions {
                download: Some(BatchResponseObjectAction {
                    header: presigned
                        .headers()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect(),
                    expires_at,
                    href: presigned.uri().to_string(),
                }),
                ..Default::default()
            },
            error: None,
        };
    }

    if let Some(content_length) = result.content_length() {
        if content_length > 0 {
            match state
                .dl_limiter
                .lock()
                .await
                .request(content_length as u64)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return BatchResponseObject::error(
                        obj,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Public LFS downloads temporarily unavailable".to_string(),
                    );
                }
                Err(e) => {
                    println!("Failed to request {content_length} bytes from download limiter: {e}");
                    return BatchResponseObject::error(
                        obj,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error".to_string(),
                    );
                }
            }
        }
    }

    let Some(tag) = common::generate_tag(
        common::Claims {
            specific_claims: common::SpecificClaims::Download(obj.oid),
            repo_path: repo,
            expires_at,
        },
        &state.authz_conf.key,
    ) else {
        return BatchResponseObject::error(
            obj,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error".to_string(),
        );
    };

    let upload_path = format!(
        "{repo}/info/lfs/objects/{}/{}/{}",
        common::HexByte(obj.oid[0]),
        common::HexByte(obj.oid[1]),
        obj.oid,
    );

    BatchResponseObject {
        oid: obj.oid,
        size: obj.size,
        authenticated: Some(true),
        actions: BatchResponseObjectActions {
            download: Some(BatchResponseObjectAction {
                header: {
                    let mut map = HashMap::new();
                    map.insert(
                        "Authorization".to_string(),
                        format!("Gitolfs3-Hmac-Sha256 {tag} {}", expires_at.timestamp()),
                    );
                    map
                },
                expires_at,
                href: format!("{}/{upload_path}", state.base_url),
            }),
            ..Default::default()
        },
        error: None,
    }
}

struct AuthorizationConfig {
    trusted_forwarded_hosts: HashSet<String>,
    key: common::Key,
}

struct Trusted(bool);

fn forwarded_from_trusted_host(
    headers: &HeaderMap,
    trusted: &HashSet<String>,
) -> Result<bool, GitLfsErrorResponse<'static>> {
    if let Some(forwarded_host) = headers.get("X-Forwarded-Host") {
        if let Ok(forwarded_host) = forwarded_host.to_str() {
            if trusted.contains(forwarded_host) {
                return Ok(true);
            }
        } else {
            return Err(make_error_resp(
                StatusCode::NOT_FOUND,
                "Invalid X-Forwarded-Host header",
            ));
        }
    }
    Ok(false)
}

const REPO_NOT_FOUND: GitLfsErrorResponse =
    make_error_resp(StatusCode::NOT_FOUND, "Repository not found");

fn authorize_batch(
    conf: &AuthorizationConfig,
    repo_path: &str,
    public: bool,
    operation: common::Operation,
    headers: &HeaderMap,
) -> Result<Trusted, GitLfsErrorResponse<'static>> {
    // - No authentication required for downloading exported repos
    // - When authenticated:
    //   - Download / upload over presigned URLs
    // - When accessing over Tailscale:
    //   - No authentication required for downloading from any repo

    let claims = VerifyClaimsInput {
        specific_claims: common::SpecificClaims::BatchApi(operation),
        repo_path,
    };
    if !verify_claims(conf, &claims, headers)? {
        return authorize_batch_unauthenticated(conf, public, operation, headers);
    }
    Ok(Trusted(true))
}

fn authorize_batch_unauthenticated(
    conf: &AuthorizationConfig,
    public: bool,
    operation: common::Operation,
    headers: &HeaderMap,
) -> Result<Trusted, GitLfsErrorResponse<'static>> {
    let trusted = forwarded_from_trusted_host(headers, &conf.trusted_forwarded_hosts)?;
    match operation {
        common::Operation::Upload => {
            // Trusted users can clone all repositories (by virtue of accessing the server via a
            // trusted network). However, they can not push without proper authentication. Untrusted
            // users who are also not authenticated should not need to know which repositories exists.
            // Therefore, we tell untrusted && unauthenticated users that the repo doesn't exist, but
            // tell trusted users that they need to authenticate.
            if !trusted {
                return Err(REPO_NOT_FOUND);
            }
            Err(make_error_resp(
                StatusCode::FORBIDDEN,
                "Authentication required to upload",
            ))
        }
        common::Operation::Download => {
            // Again, trusted users can see all repos. For untrusted users, we first need to check
            // whether the repo is public before we authorize. If the user is untrusted and the
            // repo isn't public, we just act like it doesn't even exist.
            if !trusted {
                if !public {
                    return Err(REPO_NOT_FOUND);
                }
                return Ok(Trusted(false));
            }
            Ok(Trusted(true))
        }
    }
}

fn repo_exists(name: &str) -> bool {
    let Ok(metadata) = std::fs::metadata(name) else {
        return false;
    };
    metadata.is_dir()
}

fn is_repo_public(name: &str) -> Option<bool> {
    if !repo_exists(name) {
        return None;
    }
    match std::fs::metadata(format!("{name}/git-daemon-export-ok")) {
        Ok(metadata) if metadata.is_file() => Some(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
        _ => None,
    }
}

async fn batch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RepositoryName(repo): RepositoryName,
    GitLfsJson(Json(payload)): GitLfsJson<BatchRequest>,
) -> Response {
    let Some(public) = is_repo_public(&repo) else {
        return REPO_NOT_FOUND.into_response();
    };
    let Trusted(trusted) = match authorize_batch(
        &state.authz_conf,
        &repo,
        public,
        payload.operation,
        &headers,
    ) {
        Ok(authn) => authn,
        Err(e) => return e.into_response(),
    };

    if !headers
        .get_all("Accept")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(is_git_lfs_json_mimetype)
    {
        let message = format!("Expected `{LFS_MIME}` in list of acceptable response media types");
        return make_error_resp(StatusCode::NOT_ACCEPTABLE, &message).into_response();
    }

    if payload.hash_algo != HashAlgo::Sha256 {
        let message = "Unsupported hashing algorithm specified";
        return make_error_resp(StatusCode::CONFLICT, message).into_response();
    }
    if !payload.transfers.is_empty() && !payload.transfers.contains(&TransferAdapter::Basic) {
        let message = "Unsupported transfer adapter specified (supported: basic)";
        return make_error_resp(StatusCode::CONFLICT, message).into_response();
    }

    let mut resp = BatchResponse {
        transfer: TransferAdapter::Basic,
        objects: vec![],
        hash_algo: HashAlgo::Sha256,
    };
    for obj in payload.objects {
        match payload.operation {
            common::Operation::Download => resp
                .objects
                .push(handle_download_object(&state, &repo, &obj, trusted).await),
            common::Operation::Upload => {
                if let Some(obj_resp) = handle_upload_object(&state, &repo, &obj).await {
                    resp.objects.push(obj_resp);
                }
            }
        };
    }
    GitLfsJson(Json(resp)).into_response()
}

#[derive(Deserialize, Copy, Clone)]
#[serde(remote = "Self")]
struct FileParams {
    oid0: common::HexByte,
    oid1: common::HexByte,
    oid: common::Oid,
}

impl<'de> Deserialize<'de> for FileParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let unchecked @ FileParams {
            oid0: common::HexByte(oid0),
            oid1: common::HexByte(oid1),
            oid,
        } = FileParams::deserialize(deserializer)?;
        if oid0 != oid.as_bytes()[0] {
            return Err(de::Error::custom(
                "first OID path part does not match first byte of full OID",
            ));
        }
        if oid1 != oid.as_bytes()[1] {
            return Err(de::Error::custom(
                "second OID path part does not match first byte of full OID",
            ));
        }
        Ok(unchecked)
    }
}

pub struct VerifyClaimsInput<'a> {
    pub specific_claims: common::SpecificClaims,
    pub repo_path: &'a str,
}

fn verify_claims(
    conf: &AuthorizationConfig,
    claims: &VerifyClaimsInput,
    headers: &HeaderMap,
) -> Result<bool, GitLfsErrorResponse<'static>> {
    const INVALID_AUTHZ_HEADER: GitLfsErrorResponse =
        make_error_resp(StatusCode::BAD_REQUEST, "Invalid authorization header");

    let Some(authz) = headers.get(header::AUTHORIZATION) else {
        return Ok(false);
    };
    let authz = authz.to_str().map_err(|_| INVALID_AUTHZ_HEADER)?;
    let val = authz
        .strip_prefix("Gitolfs3-Hmac-Sha256 ")
        .ok_or(INVALID_AUTHZ_HEADER)?;
    let (tag, expires_at) = val.split_once(' ').ok_or(INVALID_AUTHZ_HEADER)?;
    let tag: common::Digest<32> = tag.parse().map_err(|_| INVALID_AUTHZ_HEADER)?;
    let expires_at: i64 = expires_at.parse().map_err(|_| INVALID_AUTHZ_HEADER)?;
    let expires_at = DateTime::<Utc>::from_timestamp(expires_at, 0).ok_or(INVALID_AUTHZ_HEADER)?;
    let expected_tag = common::generate_tag(
        common::Claims {
            specific_claims: claims.specific_claims,
            repo_path: claims.repo_path,
            expires_at,
        },
        &conf.key,
    )
    .ok_or_else(|| make_error_resp(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"))?;
    if tag != expected_tag {
        return Err(INVALID_AUTHZ_HEADER);
    }

    Ok(true)
}

fn authorize_get(
    conf: &AuthorizationConfig,
    repo_path: &str,
    oid: common::Oid,
    headers: &HeaderMap,
) -> Result<(), GitLfsErrorResponse<'static>> {
    let claims = VerifyClaimsInput {
        specific_claims: common::SpecificClaims::Download(oid),
        repo_path,
    };
    if !verify_claims(conf, &claims, headers)? {
        return Err(make_error_resp(
            StatusCode::UNAUTHORIZED,
            "Repository not found",
        ));
    }
    Ok(())
}

async fn obj_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RepositoryName(repo): RepositoryName,
    Path(FileParams { oid0, oid1, oid }): Path<FileParams>,
) -> Response {
    if let Err(e) = authorize_get(&state.authz_conf, &repo, oid, &headers) {
        return e.into_response();
    }

    let full_path = format!("{repo}/lfs/objects/{}/{}/{}", oid0, oid1, oid);
    let result = match state
        .s3_client
        .get_object()
        .bucket(&state.s3_bucket)
        .key(full_path)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
    {
        Ok(result) => result,
        Err(e) => {
            println!("Failed to GetObject (repo {repo}, OID {oid}): {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query object information",
            )
                .into_response();
        }
    };

    let mut headers = header::HeaderMap::new();
    if let Some(content_type) = result.content_type {
        let Ok(header_value) = content_type.try_into() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Object has invalid content type",
            )
                .into_response();
        };
        headers.insert(header::CONTENT_TYPE, header_value);
    }
    if let Some(content_length) = result.content_length {
        headers.insert(header::CONTENT_LENGTH, content_length.into());
    }

    let async_read = result.body.into_async_read();
    let stream = tokio_util::io::ReaderStream::new(async_read);
    let body = axum::body::Body::from_stream(stream);

    (headers, body).into_response()
}

struct DownloadLimiter {
    current: u64,
    limit: u64,
}

impl DownloadLimiter {
    async fn new(limit: u64) -> DownloadLimiter {
        let dlimit_str = match tokio::fs::read_to_string(".gitolfs3-dlimit").await {
            Ok(dlimit_str) => dlimit_str,
            Err(e) => {
                println!("Failed to read download counter, assuming 0: {e}");
                return DownloadLimiter { current: 0, limit };
            }
        };
        let current: u64 = match dlimit_str
            .parse()
            .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e))
        {
            Ok(current) => current,
            Err(e) => {
                println!("Failed to read download counter, assuming 0: {e}");
                return DownloadLimiter { current: 0, limit };
            }
        };
        DownloadLimiter { current, limit }
    }

    async fn request(&mut self, n: u64) -> tokio::io::Result<bool> {
        if self.current + n > self.limit {
            return Ok(false);
        }
        self.current += n;
        self.write_new_count().await?;
        Ok(true)
    }

    async fn reset(&mut self) {
        self.current = 0;
        if let Err(e) = self.write_new_count().await {
            println!("Failed to reset download counter: {e}");
        }
    }

    async fn write_new_count(&self) -> tokio::io::Result<()> {
        let cwd = tokio::fs::File::open(std::env::current_dir()?).await?;
        let mut file = tokio::fs::File::create(".gitolfs3-dlimit.tmp").await?;
        file.write_all(self.current.to_string().as_bytes()).await?;
        file.sync_all().await?;
        tokio::fs::rename(".gitolfs3-dlimit.tmp", ".gitolfs3-dlimit").await?;
        cwd.sync_all().await
    }
}

#[test]
fn test_mimetype() {
    assert!(is_git_lfs_json_mimetype("application/vnd.git-lfs+json"));
    assert!(!is_git_lfs_json_mimetype("application/vnd.git-lfs"));
    assert!(!is_git_lfs_json_mimetype("application/json"));
    assert!(is_git_lfs_json_mimetype(
        "application/vnd.git-lfs+json; charset=utf-8"
    ));
    assert!(is_git_lfs_json_mimetype(
        "application/vnd.git-lfs+json; charset=UTF-8"
    ));
    assert!(!is_git_lfs_json_mimetype(
        "application/vnd.git-lfs+json; charset=ISO-8859-1"
    ));
}

#[test]
fn test_deserialize() {
    let json = r#"{"operation":"upload","objects":[{"oid":"8f4123f9a7181f488c5e111d82cefd992e461ae5df01fd2254399e6e670b2d3c","size":170904}],
                   "transfers":["lfs-standalone-file","basic","ssh"],"ref":{"name":"refs/heads/main"},"hash_algo":"sha256"}"#;
    let expected = BatchRequest {
        operation: common::Operation::Upload,
        objects: vec![BatchRequestObject {
            oid: "8f4123f9a7181f488c5e111d82cefd992e461ae5df01fd2254399e6e670b2d3c"
                .parse()
                .unwrap(),
            size: 170904,
        }],
        transfers: vec![
            TransferAdapter::Unknown,
            TransferAdapter::Basic,
            TransferAdapter::Unknown,
        ],
        hash_algo: HashAlgo::Sha256,
    };
    assert_eq!(
        serde_json::from_str::<BatchRequest>(json).unwrap(),
        expected
    );
}

#[test]
fn test_validate_claims() {
    let key = "00232f7a019bd34e3921ee6c5f04caf48a4489d1be5d1999038950a7054e0bfea369ce2becc0f13fd3c69f8af2384a25b7ac2d52eb52c33722f3c00c50d4c9c2";
    let key: common::Key = key.parse().unwrap();

    let claims = common::Claims {
        expires_at: Utc::now() + std::time::Duration::from_secs(5 * 60),
        repo_path: "lfs-test.git",
        specific_claims: common::SpecificClaims::BatchApi(common::Operation::Download),
    };
    let tag = common::generate_tag(claims, &key).unwrap();
    let header_value = format!(
        "Gitolfs3-Hmac-Sha256 {tag} {}",
        claims.expires_at.timestamp()
    );

    let conf = AuthorizationConfig {
        key,
        trusted_forwarded_hosts: HashSet::new(),
    };
    let verification_claims = VerifyClaimsInput {
        repo_path: claims.repo_path,
        specific_claims: claims.specific_claims,
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, header_value.try_into().unwrap());

    assert!(verify_claims(&conf, &verification_claims, &headers).unwrap());
}
