use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use aws_sdk_s3::operation::head_object::HeadObjectOutput;
use axum::extract::rejection;
use axum::extract::FromRequest;
use axum::extract::Path;
use axum::extract::State;
use axum::http::header;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::response::Response;
use axum::Json;
use axum::ServiceExt;
use base64::prelude::*;
use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
use common::HexByte;
use serde::de;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use tower::Layer;

use axum::{
    async_trait,
    extract::{FromRequestParts, OriginalUri, Request},
    http::{request::Parts, StatusCode, Uri},
    response::IntoResponse,
    routing::{get, post, put},
    Extension, Router,
};

use serde_json::json;

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

    let path_and_query = uri.path_and_query().unwrap();
    let Some((repo, path)) = path_and_query.path().split_once("/info/lfs/objects") else {
        return Err(StatusCode::NOT_FOUND);
    };
    let repo = repo
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string();
    if !path.starts_with("/") || !repo.ends_with(".git") {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = match path_and_query.query() {
        None => path.try_into().ok(),
        Some(q) => format!("{path}?{q}").try_into().ok(),
    };
    let new_uri = Uri::from_parts(parts).unwrap();

    *req.uri_mut() = new_uri;
    req.extensions_mut().insert(original_uri);
    req.extensions_mut().insert(RepositoryName(repo));

    Ok(req)
}

struct AppState {
    s3_client: aws_sdk_s3::Client,
    s3_bucket: String,
    authz_conf: AuthorizationConfig,
}

fn get_s3_client() -> aws_sdk_s3::Client {
    let access_key_id = std::env::var("S3_ACCESS_KEY_ID").unwrap();
    let secret_access_key = std::env::var("S3_SECRET_ACCESS_KEY").unwrap();

    let credentials = aws_sdk_s3::config::Credentials::new(
        access_key_id,
        secret_access_key,
        None,
        None,
        "gitolfs3-env",
    );
    let config = aws_config::SdkConfig::builder()
        .endpoint_url(std::env::var("S3_ENDPOINT").unwrap())
        .credentials_provider(aws_sdk_s3::config::SharedCredentialsProvider::new(
            credentials,
        ))
        .build();
    aws_sdk_s3::Client::new(&config)
}

#[tokio::main]
async fn main() {
    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    let key_path = std::env::var("GITOLFS3_KEY_PATH").unwrap();
    let key = common::load_key(&key_path).unwrap();
    let trusted_forwarded_hosts = std::env::var("GITOLFS3_TRUSTED_FORWARDED_HOSTS").unwrap();
    let trusted_forwarded_hosts: HashSet<String> = trusted_forwarded_hosts
        .split(',')
        .map(|s| s.to_owned())
        .collect();

    let authz_conf = AuthorizationConfig {
        key,
        trusted_forwarded_hosts,
    };

    let s3_client = get_s3_client();
    let s3_bucket = std::env::var("S3_BUCKET").unwrap();
    let shared_state = Arc::new(AppState {
        s3_client,
        s3_bucket,
        authz_conf,
    });
    let app = Router::new()
        .route("/batch", post(batch))
        .route("/:oid0/:oid1/:oid", get(obj_download))
        .route("/:oid0/:oid1/:oid", put(obj_upload))
        .with_state(shared_state);

    let middleware = axum::middleware::map_request(rewrite_url);
    let app_with_middleware = middleware.layer(app);

    axum::serve(listener, app_with_middleware.into_make_service())
        .await
        .unwrap();
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
enum TransferAdapter {
    #[serde(rename = "basic")]
    Basic,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
enum HashAlgo {
    #[serde(rename = "sha256")]
    Sha256,
}

impl Default for HashAlgo {
    fn default() -> Self {
        Self::Sha256
    }
}

type Oid = common::Digest<32>;

#[derive(Debug, Deserialize, Clone)]
struct BatchRequestObject {
    oid: Oid,
    size: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BatchRef {
    name: String,
}

fn default_transfers() -> Vec<TransferAdapter> {
    vec![TransferAdapter::Basic]
}

#[derive(Deserialize)]
struct BatchRequest {
    operation: common::Operation,
    #[serde(default = "default_transfers")]
    transfers: Vec<TransferAdapter>,
    #[serde(rename = "ref")]
    reference: Option<BatchRef>,
    objects: Vec<BatchRequestObject>,
    #[serde(default)]
    hash_algo: HashAlgo,
}

#[derive(Clone)]
struct GitLfsJson<T>(Json<T>);

const LFS_MIME: &'static str = "application/vnd.git-lfs+json";

enum GitLfsJsonRejection {
    Json(rejection::JsonRejection),
    MissingGitLfsJsonContentType,
}

impl IntoResponse for GitLfsJsonRejection {
    fn into_response(self) -> Response {
        make_error_resp(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &format!("Expected request with `Content-Type: {LFS_MIME}`"),
        )
        .into_response()
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
    return is_git_lfs_json_mimetype(content_type);
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

#[derive(Serialize)]
struct GitLfsErrorData<'a> {
    message: &'a str,
}

type GitLfsErrorResponse<'a> = (StatusCode, GitLfsJson<GitLfsErrorData<'a>>);

const fn make_error_resp<'a>(code: StatusCode, message: &'a str) -> GitLfsErrorResponse {
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

#[derive(Debug, Serialize, Clone)]
struct BatchResponseObject {
    oid: Oid,
    size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    authenticated: Option<bool>,
    actions: BatchResponseObjectActions,
}

#[derive(Debug, Serialize, Clone)]
struct BatchResponse {
    transfer: TransferAdapter,
    objects: Vec<BatchResponseObject>,
    hash_algo: HashAlgo,
}

fn validate_checksum(oid: Oid, obj: &HeadObjectOutput) -> bool {
    if let Some(checksum) = obj.checksum_sha256() {
        if let Ok(checksum) = BASE64_STANDARD.decode(checksum) {
            if let Ok(checksum32b) = TryInto::<[u8; 32]>::try_into(checksum) {
                return Oid::from(checksum32b) == oid;
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

async fn handle_download_object(state: &AppState, repo: &str, obj: &BatchRequestObject, trusted: bool) -> BatchResponseObject {
    let (oid0, oid1) = (HexByte(obj.oid[0]), HexByte(obj.oid[1]));
    let full_path = format!("{repo}/lfs/objects/{}/{}/{}", oid0, oid1, obj.oid);

    let result = state
        .s3_client
        .head_object()
        .bucket(&state.s3_bucket)
        .key(full_path)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .unwrap(); // TODO: don't unwrap()
    // Scaleway actually doesn't provide SHA256 suport, but maybe in the future :)
    if !validate_checksum(obj.oid, &result) {
        todo!();
    }
    if !validate_size(obj.size, &result) {
        todo!();
    }

    let expires_in = std::time::Duration::from_secs(5 * 60);
    let expires_at = Utc::now() + expires_in;

    if trusted {
        let config = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in).unwrap();
        let presigned = state.s3_client.get_object().presigned(config).await.unwrap();
        return BatchResponseObject{
            oid: obj.oid,
            size: obj.size,
            authenticated: Some(true),
            actions: BatchResponseObjectActions {
                download: Some(BatchResponseObjectAction{
                    header: presigned.headers().map(|(k, v)| (k.to_owned(), v.to_owned())).collect(),
                    expires_at,
                    href: presigned.uri().to_string(),
                }),
                ..Default::default()
            }
        };
    }
    todo!();
}

struct AuthorizationConfig {
    trusted_forwarded_hosts: HashSet<String>,
    key: common::Key,
}

struct Trusted(bool);

fn forwarded_for_trusted_host(
    headers: &HeaderMap,
    trusted: &HashSet<String>,
) -> Result<bool, GitLfsErrorResponse<'static>> {
    if let Some(forwarded_for) = headers.get("X-Forwarded-For") {
        if let Ok(forwarded_for) = forwarded_for.to_str() {
            if trusted.contains(forwarded_for) {
                return Ok(true);
            }
        } else {
            return Err(make_error_resp(
                StatusCode::NOT_FOUND,
                "Invalid X-Forwarded-For header",
            ));
        }
    }
    return Ok(false);
}
const REPO_NOT_FOUND: GitLfsErrorResponse =
    make_error_resp(StatusCode::NOT_FOUND, "Repository not found");

fn authorize(
    conf: &AuthorizationConfig,
    headers: &HeaderMap,
    repo_path: &str,
    public: bool,
    operation: common::Operation,
) -> Result<Trusted, GitLfsErrorResponse<'static>> {
    // - No authentication required for downloading exported repos
    // - When authenticated:
    //   - Download / upload over presigned URLs
    // - When accessing over Tailscale:
    //   - No authentication required for downloading from any repo

    const INVALID_AUTHZ_HEADER: GitLfsErrorResponse =
        make_error_resp(StatusCode::BAD_REQUEST, "Invalid authorization header");

    if let Some(authz) = headers.get(header::AUTHORIZATION) {
        if let Ok(authz) = authz.to_str() {
            if let Some(val) = authz.strip_prefix("Gitolfs3-Hmac-Sha256 ") {
                let Some((tag, expires_at)) = val.split_once(' ') else {
                    return Err(INVALID_AUTHZ_HEADER);
                };
                let Ok(tag): Result<common::Digest<32>, _> = tag.parse() else {
                    return Err(INVALID_AUTHZ_HEADER);
                };
                let Ok(expires_at): Result<i64, _> = expires_at.parse() else {
                    return Err(INVALID_AUTHZ_HEADER);
                };
                let Some(expires_at) = DateTime::<Utc>::from_timestamp(expires_at, 0) else {
                    return Err(INVALID_AUTHZ_HEADER);
                };
                let Some(expected_tag) = common::generate_tag(
                    common::Claims {
                        auth_type: common::AuthType::GitLfsAuthenticate,
                        repo_path,
                        expires_at,
                        operation,
                    },
                    &conf.key,
                ) else {
                    return Err(INVALID_AUTHZ_HEADER);
                };
                if tag == expected_tag {
                    return Ok(Trusted(true));
                } else {
                    return Err(INVALID_AUTHZ_HEADER);
                }
            } else {
                return Err(INVALID_AUTHZ_HEADER);
            }
        } else {
            return Err(INVALID_AUTHZ_HEADER);
        }
    }

    let trusted = forwarded_for_trusted_host(headers, &conf.trusted_forwarded_hosts)?;
    if operation != common::Operation::Download {
        if trusted {
            return Err(make_error_resp(
                StatusCode::FORBIDDEN,
                "Authentication required to upload",
            ));
        }
        return Err(REPO_NOT_FOUND);
    }
    if trusted {
        return Ok(Trusted(true));
    }

    if public {
        Ok(Trusted(false))
    } else {
        Err(REPO_NOT_FOUND)
    }
}

fn repo_exists(name: &str) -> bool {
    let Ok(metadata) = std::fs::metadata(name) else {
        return false;
    };
    return metadata.is_dir();
}

fn is_repo_public(name: &str) -> Option<bool> {
    if !repo_exists(name) {
        return None;
    }
    std::fs::metadata(format!("{name}/git-daemon-export-ok"))
        .ok()?
        .is_file()
        .into()
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
    let Trusted(trusted) = match authorize(
        &state.authz_conf,
        &headers,
        &repo,
        public,
        payload.operation,
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

    let resp: BatchResponse;
    for obj in payload.objects {
        handle_download_object(&state, &repo, &obj, trusted).await;
        //        match payload.operation {
        //            Operation::Download => resp.objects.push(handle_download_object(repo, obj));,
        //            Operation::Upload => resp.objects.push(handle_upload_object(repo, obj)),
        //        };
    }

    format!("hi from {repo}\n").into_response()
}

#[derive(Deserialize, Copy, Clone)]
#[serde(remote = "Self")]
struct FileParams {
    oid0: HexByte,
    oid1: HexByte,
    oid: Oid,
}

impl<'de> Deserialize<'de> for FileParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let unchecked @ FileParams {
            oid0: HexByte(oid0),
            oid1: HexByte(oid1),
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

async fn obj_download(Path(FileParams { oid0, oid1, oid }): Path<FileParams>) {}

async fn obj_upload(Path(FileParams { oid0, oid1, oid }): Path<FileParams>) {}
