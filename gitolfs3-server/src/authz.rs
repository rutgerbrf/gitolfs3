use std::collections::HashSet;

use axum::http;
use chrono::{DateTime, Utc};
use gitolfs3_common::{generate_tag, Claims, Digest, Oid, Operation, SpecificClaims};

use crate::{
    api::{make_error_resp, GitLfsErrorResponse, REPO_NOT_FOUND},
    config::AuthorizationConfig,
};

pub struct Trusted(pub bool);

pub fn authorize_batch(
    conf: &AuthorizationConfig,
    repo_path: &str,
    public: bool,
    operation: Operation,
    headers: &http::HeaderMap,
) -> Result<Trusted, GitLfsErrorResponse<'static>> {
    // - No authentication required for downloading exported repos
    // - When authenticated:
    //   - Download / upload over presigned URLs
    // - When accessing over Tailscale:
    //   - No authentication required for downloading from any repo

    let claims = VerifyClaimsInput {
        specific_claims: SpecificClaims::BatchApi(operation),
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
    operation: Operation,
    headers: &http::HeaderMap,
) -> Result<Trusted, GitLfsErrorResponse<'static>> {
    let trusted = forwarded_from_trusted_host(headers, &conf.trusted_forwarded_hosts)?;
    match operation {
        Operation::Upload => {
            // Trusted users can clone all repositories (by virtue of accessing the server via a
            // trusted network). However, they can not push without proper authentication. Untrusted
            // users who are also not authenticated should not need to know which repositories exists.
            // Therefore, we tell untrusted && unauthenticated users that the repo doesn't exist, but
            // tell trusted users that they need to authenticate.
            if !trusted {
                return Err(REPO_NOT_FOUND);
            }
            Err(make_error_resp(
                http::StatusCode::FORBIDDEN,
                "Authentication required to upload",
            ))
        }
        Operation::Download => {
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

pub fn authorize_get(
    conf: &AuthorizationConfig,
    repo_path: &str,
    oid: Oid,
    headers: &http::HeaderMap,
) -> Result<(), GitLfsErrorResponse<'static>> {
    let claims = VerifyClaimsInput {
        specific_claims: SpecificClaims::Download(oid),
        repo_path,
    };
    if !verify_claims(conf, &claims, headers)? {
        return Err(make_error_resp(
            http::StatusCode::UNAUTHORIZED,
            "Repository not found",
        ));
    }
    Ok(())
}

fn forwarded_from_trusted_host(
    headers: &http::HeaderMap,
    trusted: &HashSet<String>,
) -> Result<bool, GitLfsErrorResponse<'static>> {
    if let Some(forwarded_host) = headers.get("X-Forwarded-Host") {
        if let Ok(forwarded_host) = forwarded_host.to_str() {
            if trusted.contains(forwarded_host) {
                return Ok(true);
            }
        } else {
            return Err(make_error_resp(
                http::StatusCode::NOT_FOUND,
                "Invalid X-Forwarded-Host header",
            ));
        }
    }
    Ok(false)
}

struct VerifyClaimsInput<'a> {
    specific_claims: SpecificClaims,
    repo_path: &'a str,
}

fn verify_claims(
    conf: &AuthorizationConfig,
    claims: &VerifyClaimsInput,
    headers: &http::HeaderMap,
) -> Result<bool, GitLfsErrorResponse<'static>> {
    const INVALID_AUTHZ_HEADER: GitLfsErrorResponse = make_error_resp(
        http::StatusCode::BAD_REQUEST,
        "Invalid authorization header",
    );

    let Some(authz) = headers.get(http::header::AUTHORIZATION) else {
        return Ok(false);
    };
    let authz = authz.to_str().map_err(|_| INVALID_AUTHZ_HEADER)?;
    let val = authz
        .strip_prefix("Gitolfs3-Hmac-Sha256 ")
        .ok_or(INVALID_AUTHZ_HEADER)?;
    let (tag, expires_at) = val.split_once(' ').ok_or(INVALID_AUTHZ_HEADER)?;
    let tag: Digest<32> = tag.parse().map_err(|_| INVALID_AUTHZ_HEADER)?;
    let expires_at: i64 = expires_at.parse().map_err(|_| INVALID_AUTHZ_HEADER)?;
    let expires_at = DateTime::<Utc>::from_timestamp(expires_at, 0).ok_or(INVALID_AUTHZ_HEADER)?;
    let expected_tag = generate_tag(
        Claims {
            specific_claims: claims.specific_claims,
            repo_path: claims.repo_path,
            expires_at,
        },
        &conf.key,
    )
    .ok_or_else(|| {
        make_error_resp(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error",
        )
    })?;
    if tag != expected_tag {
        return Err(INVALID_AUTHZ_HEADER);
    }

    Ok(true)
}

#[test]
fn test_validate_claims() {
    use gitolfs3_common::Key;

    let key = "00232f7a019bd34e3921ee6c5f04caf48a4489d1be5d1999038950a7054e0bfea369ce2becc0f13fd3c69f8af2384a25b7ac2d52eb52c33722f3c00c50d4c9c2";
    let key: Key = key.parse().unwrap();

    let claims = Claims {
        expires_at: Utc::now() + std::time::Duration::from_secs(5 * 60),
        repo_path: "lfs-test.git",
        specific_claims: SpecificClaims::BatchApi(Operation::Download),
    };
    let tag = generate_tag(claims, &key).unwrap();
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
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        header_value.try_into().unwrap(),
    );

    assert!(verify_claims(&conf, &verification_claims, &headers).unwrap());
}
