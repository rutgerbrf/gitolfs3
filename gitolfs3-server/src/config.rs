use std::collections::HashSet;

use gitolfs3_common::{load_key, Key};

pub struct Config {
    pub listen_addr: (String, u16),
    pub base_url: String,
    pub authz_conf: AuthorizationConfig,
    pub s3_client: aws_sdk_s3::Client,
    pub s3_bucket: String,
    pub download_limit: u64,
}

pub struct AuthorizationConfig {
    pub trusted_forwarded_hosts: HashSet<String>,
    pub key: Key,
}

impl Config {
    pub fn load() -> Result<Self, String> {
        let env = match Env::load() {
            Ok(env) => env,
            Err(e) => return Err(format!("failed to load configuration: {e}")),
        };

        let s3_client = match create_s3_client(&env) {
            Ok(s3_client) => s3_client,
            Err(e) => return Err(format!("failed to create S3 client: {e}")),
        };
        let key = match load_key(&env.key_path) {
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

fn create_s3_client(env: &Env) -> Result<aws_sdk_s3::Client, std::io::Error> {
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

fn require_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .map_err(|_| format!("environment variable {name} should be defined and valid"))
}
