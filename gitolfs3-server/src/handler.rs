use std::{collections::HashMap, sync::Arc};

use aws_sdk_s3::{error::SdkError, operation::head_object::HeadObjectOutput};
use axum::{
    extract::{Path, State},
    http,
    response::{IntoResponse, Response},
    Json,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Utc;
use gitolfs3_common::{generate_tag, Claims, HexByte, Oid, Operation, SpecificClaims};
use serde::{de, Deserialize};
use tokio::sync::Mutex;

use crate::{
    api::{
        is_git_lfs_json_mimetype, make_error_resp, BatchRequest, BatchRequestObject, BatchResponse,
        BatchResponseObject, BatchResponseObjectAction, BatchResponseObjectActions, GitLfsJson,
        HashAlgo, RepositoryName, TransferAdapter, LFS_MIME, REPO_NOT_FOUND,
    },
    authz::{authorize_batch, authorize_get, Trusted},
    config::AuthorizationConfig,
    dlimit::DownloadLimiter,
};

pub struct AppState {
    pub s3_client: aws_sdk_s3::Client,
    pub s3_bucket: String,
    pub authz_conf: AuthorizationConfig,
    // Should not end with a slash.
    pub base_url: String,
    pub dl_limiter: Arc<Mutex<DownloadLimiter>>,
}

async fn handle_download_object(
    state: &AppState,
    repo: &str,
    obj: &BatchRequestObject,
    trusted: bool,
) -> BatchResponseObject {
    let (oid0, oid1) = (HexByte(obj.oid[0]), HexByte(obj.oid[1]));
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
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query object information".to_string(),
            );
        }
    };

    // Scaleway actually doesn't provide SHA256 support, but maybe in the future :)
    if !s3_validate_checksum(obj.oid, &result) {
        return BatchResponseObject::error(
            obj,
            http::StatusCode::UNPROCESSABLE_ENTITY,
            "Object corrupted".to_string(),
        );
    }
    if !s3_validate_size(obj.size, &result) {
        return BatchResponseObject::error(
            obj,
            http::StatusCode::UNPROCESSABLE_ENTITY,
            "Incorrect size specified (or object corrupted)".to_string(),
        );
    }

    let expires_in = std::time::Duration::from_secs(5 * 60);
    let expires_at = Utc::now() + expires_in;

    if trusted {
        let Ok(config) = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in) else {
            return BatchResponseObject::error(
                obj,
                http::StatusCode::INTERNAL_SERVER_ERROR,
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
                http::StatusCode::INTERNAL_SERVER_ERROR,
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
                        http::StatusCode::SERVICE_UNAVAILABLE,
                        "Public LFS downloads temporarily unavailable".to_string(),
                    );
                }
                Err(e) => {
                    println!("Failed to request {content_length} bytes from download limiter: {e}");
                    return BatchResponseObject::error(
                        obj,
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error".to_string(),
                    );
                }
            }
        }
    }

    let Some(tag) = generate_tag(
        Claims {
            specific_claims: SpecificClaims::Download(obj.oid),
            repo_path: repo,
            expires_at,
        },
        &state.authz_conf.key,
    ) else {
        return BatchResponseObject::error(
            obj,
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error".to_string(),
        );
    };

    let upload_path = format!(
        "{repo}/info/lfs/objects/{}/{}/{}",
        HexByte(obj.oid[0]),
        HexByte(obj.oid[1]),
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

#[derive(Deserialize, Copy, Clone)]
#[serde(remote = "Self")]
pub struct FileParams {
    oid0: HexByte,
    oid1: HexByte,
    oid: Oid,
}

impl<'de> Deserialize<'de> for FileParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let unchecked @ Self {
            oid0: HexByte(oid0),
            oid1: HexByte(oid1),
            oid,
        } = Self::deserialize(deserializer)?;
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

pub async fn handle_obj_download(
    State(state): State<Arc<AppState>>,
    headers: http::HeaderMap,
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
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query object information",
            )
                .into_response();
        }
    };

    let mut headers = http::header::HeaderMap::new();
    if let Some(content_type) = result.content_type {
        let Ok(header_value) = content_type.try_into() else {
            return (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "Object has invalid content type",
            )
                .into_response();
        };
        headers.insert(http::header::CONTENT_TYPE, header_value);
    }
    if let Some(content_length) = result.content_length {
        headers.insert(http::header::CONTENT_LENGTH, content_length.into());
    }

    let async_read = result.body.into_async_read();
    let stream = tokio_util::io::ReaderStream::new(async_read);
    let body = axum::body::Body::from_stream(stream);

    (headers, body).into_response()
}

async fn handle_upload_object(
    state: &AppState,
    repo: &str,
    obj: &BatchRequestObject,
) -> Option<BatchResponseObject> {
    let (oid0, oid1) = (HexByte(obj.oid[0]), HexByte(obj.oid[1]));
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
            if s3_validate_size(obj.size, &result) && s3_validate_checksum(obj.oid, &result) {
                return None;
            }
        }
        Err(SdkError::ServiceError(e)) if e.err().is_not_found() => {}
        Err(e) => {
            println!("Failed to HeadObject (repo {repo}, OID {}): {e}", obj.oid);
            return Some(BatchResponseObject::error(
                obj,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query object information".to_string(),
            ));
        }
    };

    let expires_in = std::time::Duration::from_secs(5 * 60);
    let expires_at = Utc::now() + expires_in;

    let Ok(config) = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in) else {
        return Some(BatchResponseObject::error(
            obj,
            http::StatusCode::INTERNAL_SERVER_ERROR,
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
            http::StatusCode::INTERNAL_SERVER_ERROR,
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

pub async fn handle_batch(
    State(state): State<Arc<AppState>>,
    headers: http::HeaderMap,
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
        return make_error_resp(http::StatusCode::NOT_ACCEPTABLE, &message).into_response();
    }

    if payload.hash_algo != HashAlgo::Sha256 {
        let message = "Unsupported hashing algorithm specified";
        return make_error_resp(http::StatusCode::CONFLICT, message).into_response();
    }
    if !payload.transfers.is_empty() && !payload.transfers.contains(&TransferAdapter::Basic) {
        let message = "Unsupported transfer adapter specified (supported: basic)";
        return make_error_resp(http::StatusCode::CONFLICT, message).into_response();
    }

    let mut resp = BatchResponse {
        transfer: TransferAdapter::Basic,
        objects: vec![],
        hash_algo: HashAlgo::Sha256,
    };
    for obj in payload.objects {
        match payload.operation {
            Operation::Download => resp
                .objects
                .push(handle_download_object(&state, &repo, &obj, trusted).await),
            Operation::Upload => {
                if let Some(obj_resp) = handle_upload_object(&state, &repo, &obj).await {
                    resp.objects.push(obj_resp);
                }
            }
        };
    }
    GitLfsJson(Json(resp)).into_response()
}

fn s3_validate_checksum(oid: Oid, obj: &HeadObjectOutput) -> bool {
    if let Some(checksum) = obj.checksum_sha256() {
        if let Ok(checksum) = BASE64_STANDARD.decode(checksum) {
            if let Ok(checksum32b) = TryInto::<[u8; 32]>::try_into(checksum) {
                return Oid::from(checksum32b) == oid;
            }
        }
    }
    true
}

fn s3_validate_size(expected: i64, obj: &HeadObjectOutput) -> bool {
    if let Some(length) = obj.content_length() {
        return length == expected;
    }
    true
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
