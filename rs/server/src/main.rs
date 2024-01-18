use std::collections::HashMap;

use awscreds::Credentials;
use axum::extract::rejection;
use axum::extract::FromRequest;
use axum::extract::Path;
use axum::http::header;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::response::Response;
use axum::Json;
use chrono::DateTime;
use chrono::Utc;
use common::HexByte;
use common::Operation;
use s3::Bucket;
use serde::de;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use tower_service::Service;

use axum::{
    async_trait,
    extract::{FromRequestParts, OriginalUri, Request},
    http::{request::Parts, StatusCode, Uri},
    response::IntoResponse,
    routing::{any, get, post, put},
    Extension, Router,
};

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

#[tokio::main]
async fn main() {
    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let mut app = Router::new()
        .route("/batch", post(batch))
        .route("/:oid0/:oid1/:oid", get(obj_download))
        .route("/:oid0/:oid1/:oid", put(obj_upload));
    axum::serve(
        listener,
        any(|mut req: Request| async move {
            let uri = req.uri();
            let original_uri = OriginalUri(uri.clone());

            let path_and_query = uri.path_and_query().unwrap();
            let Some((repo, path)) = path_and_query.path().split_once("/info/lfs/objects") else {
                return Ok(StatusCode::NOT_FOUND.into_response());
            };
            let repo = repo
                .trim_start_matches('/')
                .trim_end_matches('/')
                .to_string();
            if !path.starts_with("/") || !repo.ends_with(".git") {
                return Ok(StatusCode::NOT_FOUND.into_response());
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

            app.call(req).await
        }),
    )
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
        (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("Expected request with `Content-Type: {LFS_MIME}`"),
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
            HeaderValue::from_static("application/vnd.git-lfs+json"),
        );
        resp
    }
}

#[derive(Debug, Serialize, Clone)]
struct BatchResponseObjectAction {
    href: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    header: HashMap<String, String>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Clone)]
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
}

#[derive(Debug, Serialize, Clone)]
struct BatchResponse {
    transfer: TransferAdapter,
    objects: Vec<BatchResponseObject>,
    hash_algo: HashAlgo,
}

//fn handle_download_object(repo: &str, obj: &BatchRequestObject) {
//    let (oid0, oid1) = (HexByte(obj.oid[0]), HexByte(obj.oid[1]));
//    let full_path = format!("{repo}/lfs/objects/{}/{}/{}", oid0, oid1, obj.oid);
//
//    let bucket_anme = "asdfasdf";
//    let region = s3::Region::Custom {
//        region: "nl-ams".to_string(),
//        endpoint: "rg.nl-ams.swc.cloud".to_string()
//    };
//    let credentials = Credentials::new(None, None, None, None, None).unwrap();
//    let bucket = Bucket::new(bucket_anme, region, credentials).unwrap();
//}

async fn batch(
    header: HeaderMap,
    RepositoryName(repo): RepositoryName,
    GitLfsJson(Json(payload)): GitLfsJson<BatchRequest>,
) -> Response {
    if !header
        .get_all("Accept")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(is_git_lfs_json_mimetype)
    {
        return (
            StatusCode::NOT_ACCEPTABLE,
            format!("Expected `{LFS_MIME}` (with UTF-8 charset) in list of acceptable response media types"),
        ).into_response();
    }

    if payload.hash_algo != HashAlgo::Sha256 {
        return (
            StatusCode::CONFLICT,
            "Unsupported hashing algorithm speicifed",
        )
            .into_response();
    }
    if !payload.transfers.is_empty() && !payload.transfers.contains(&TransferAdapter::Basic) {
        return (
            StatusCode::CONFLICT,
            "Unsupported transfer adapter specified (supported: basic)",
        )
            .into_response();
    }

    let resp: BatchResponse;
    for obj in payload.objects {
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
