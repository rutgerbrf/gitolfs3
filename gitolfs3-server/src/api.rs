use std::collections::HashMap;

use axum::{
    Extension, Json,
    extract::{FromRequest, FromRequestParts, Request, rejection},
    http,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use gitolfs3_common::{Oid, Operation};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

// ----------------------- Generic facilities ----------------------

pub type GitLfsErrorResponse<'a> = (http::StatusCode, GitLfsJson<GitLfsErrorData<'a>>);

#[derive(Debug, Serialize)]
pub struct GitLfsErrorData<'a> {
    pub message: &'a str,
}

pub const fn make_error_resp<'a>(
    code: http::StatusCode,
    message: &'a str,
) -> GitLfsErrorResponse<'a> {
    (code, GitLfsJson(Json(GitLfsErrorData { message })))
}

pub const REPO_NOT_FOUND: GitLfsErrorResponse =
    make_error_resp(http::StatusCode::NOT_FOUND, "Repository not found");

#[derive(Debug, Clone)]
pub struct GitLfsJson<T>(pub Json<T>);

pub const LFS_MIME: &str = "application/vnd.git-lfs+json";

pub enum GitLfsJsonRejection {
    Json(rejection::JsonRejection),
    MissingGitLfsJsonContentType,
}

impl IntoResponse for GitLfsJsonRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Json(rej) => rej.into_response(),
            Self::MissingGitLfsJsonContentType => make_error_resp(
                http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &format!("Expected request with `Content-Type: {LFS_MIME}`"),
            )
            .into_response(),
        }
    }
}

pub fn is_git_lfs_json_mimetype(mimetype: &str) -> bool {
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
    let Some(content_type) = req.headers().get(http::header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(content_type) = content_type.to_str() else {
        return false;
    };
    is_git_lfs_json_mimetype(content_type)
}

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
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/vnd.git-lfs+json; charset=utf-8"),
        );
        resp
    }
}

#[derive(Clone)]
pub struct RepositoryName(pub String);

pub struct RepositoryNameRejection;

impl IntoResponse for RepositoryNameRejection {
    fn into_response(self) -> Response {
        (
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "Missing repository name",
        )
            .into_response()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RepositoryName {
    type Rejection = RepositoryNameRejection;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Ok(Extension(repo_name)) = Extension::<Self>::from_request_parts(parts, state).await
        else {
            return Err(RepositoryNameRejection);
        };
        Ok(repo_name)
    }
}

// ----------------------- Git LFS Batch API -----------------------

#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
pub struct BatchRequest {
    pub operation: Operation,
    #[serde(default = "default_transfers")]
    pub transfers: Vec<TransferAdapter>,
    pub objects: Vec<BatchRequestObject>,
    #[serde(default)]
    pub hash_algo: HashAlgo,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
pub struct BatchRequestObject {
    pub oid: Oid,
    pub size: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
pub enum TransferAdapter {
    #[serde(rename = "basic")]
    Basic,
    #[serde(other)]
    Unknown,
}

fn default_transfers() -> Vec<TransferAdapter> {
    vec![TransferAdapter::Basic]
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
pub enum HashAlgo {
    #[default]
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Clone)]
pub struct BatchResponse {
    pub transfer: TransferAdapter,
    pub objects: Vec<BatchResponseObject>,
    pub hash_algo: HashAlgo,
}

#[derive(Debug, Serialize, Clone)]
pub struct BatchResponseObject {
    pub oid: Oid,
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    pub actions: BatchResponseObjectActions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BatchResponseObjectError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchResponseObjectError {
    pub code: u16,
    pub message: String,
}

impl BatchResponseObject {
    pub fn error(
        obj: &BatchRequestObject,
        code: http::StatusCode,
        message: String,
    ) -> BatchResponseObject {
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
pub struct BatchResponseObjectAction {
    pub href: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub header: HashMap<String, String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Default, Debug, Serialize, Clone)]
pub struct BatchResponseObjectActions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<BatchResponseObjectAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<BatchResponseObjectAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<BatchResponseObjectAction>,
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
        operation: Operation::Upload,
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
