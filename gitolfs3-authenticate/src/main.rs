use anyhow::{Result, anyhow, bail};
use chrono::Utc;
use gitolfs3_common::{Claims, Key, Operation, SpecificClaims, generate_tag, load_key};
use serde_json::json;
use std::{process::ExitCode, time::Duration};

fn main() -> ExitCode {
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(2);
        }
    };

    let (repo_name, operation) = match parse_cmdline() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {e}\n");
            eprintln!("Usage: git-lfs-authenticate <REPO> upload/download");
            // Exit code 2 signifies bad usage of CLI.
            return ExitCode::from(2);
        }
    };

    if !repo_exists(&repo_name) {
        eprintln!("Error: repository does not exist");
        return ExitCode::FAILURE;
    }

    let expires_at = Utc::now() + Duration::from_secs(5 * 60);
    let Some(tag) = generate_tag(
        Claims {
            specific_claims: SpecificClaims::BatchApi(operation),
            repo_path: &repo_name,
            expires_at,
        },
        config.key,
    ) else {
        eprintln!("Failed to generate validation tag");
        return ExitCode::FAILURE;
    };

    let response = json!({
        "header": {
            "Authorization": format!(
                "Gitolfs3-Hmac-Sha256 {tag} {}",
                expires_at.timestamp()
            ),
        },
        "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "href": format!("{}{}/info/lfs", config.href_base, repo_name),
    });
    println!("{}", response);

    ExitCode::SUCCESS
}

struct Config {
    href_base: String,
    key: Key,
}

impl Config {
    fn load() -> Result<Self> {
        let Ok(href_base) = std::env::var("GITOLFS3_HREF_BASE") else {
            bail!("invalid configuration: base URL not provided");
        };
        if !href_base.ends_with('/') {
            bail!("invalid configuration: base URL does not end with a slash");
        }

        let Ok(key_path) = std::env::var("GITOLFS3_KEY_PATH") else {
            bail!("invalid configuration: key path not provided");
        };
        let key = load_key(&key_path).map_err(|e| anyhow!("failed to load key: {e}"))?;

        Ok(Self { href_base, key })
    }
}

fn parse_cmdline() -> Result<(String, Operation)> {
    let [repo_path, op_str] = get_cmdline_args::<2>()?;
    let op: Operation = op_str
        .parse()
        .map_err(|e| anyhow!("unknown operation: {e}"))?;
    validate_repo_path(&repo_path).map_err(|e| anyhow!("invalid repository name: {e}"))?;
    Ok((repo_path.to_string(), op))
}

fn get_cmdline_args<const N: usize>() -> Result<[String; N]> {
    let args = std::env::args();
    if args.len() - 1 != N {
        bail!("got {} argument(s), expected {}", args.len() - 1, N);
    }

    // Does not allocate.
    const EMPTY_STRING: String = String::new();
    let mut values = [EMPTY_STRING; N];

    // Skip the first element; we do not care about the program name.
    for (i, arg) in args.skip(1).enumerate() {
        values[i] = arg
    }
    Ok(values)
}

fn validate_repo_path(path: &str) -> Result<()> {
    if path.len() > 100 {
        bail!("too long (more than 100 characters)");
    }
    if path.contains("//")
        || path.contains("/./")
        || path.contains("/../")
        || path.starts_with("./")
        || path.starts_with("../")
    {
        bail!("contains one or more path elements '.' and '..'");
    }
    if path.starts_with('/') {
        bail!("starts with '/', which is not allowed");
    }
    if !path.ends_with(".git") {
        bail!("missed '.git' suffix");
    }
    Ok(())
}

fn repo_exists(name: &str) -> bool {
    match std::fs::metadata(name) {
        Ok(metadata) => metadata.is_dir(),
        _ => false,
    }
}
