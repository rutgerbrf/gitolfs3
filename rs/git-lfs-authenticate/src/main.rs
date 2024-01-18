use std::{fmt, process::ExitCode, time::Duration};

use chrono::Utc;
use common::{Operation, ParseOperationError};

fn help() {
    eprintln!("Usage: git-lfs-authenticate <REPO> upload/download");
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum RepoNameError {
    TooLong,
    UnresolvedPath,
    AbsolutePath,
    MissingGitSuffix,
}

impl fmt::Display for RepoNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "too long (more than 100 characters)"),
            Self::UnresolvedPath => {
                write!(f, "contains path one or more path elements '.' and '..'")
            }
            Self::AbsolutePath => {
                write!(f, "starts with '/', which is not allowed")
            }
            Self::MissingGitSuffix => write!(f, "misses '.git' suffix"),
        }
    }
}

// Using `Result<(), E>` here instead of `Option<E>` because `None` typically signifies some error
// state with no further details provided. If we were to return an `Option` type, the user would
// have to first transform it into a `Result` type in order to use the `?` operator, meaning that
// they would have to the following operation to get the type into the right shape:
// `validate_repo_path(path).map_or(Ok(()), Err)`. That would not be very ergonomic.
fn validate_repo_path(path: &str) -> Result<(), RepoNameError> {
    if path.len() > 100 {
        return Err(RepoNameError::TooLong);
    }
    if path.contains("//")
        || path.contains("/./")
        || path.contains("/../")
        || path.starts_with("./")
        || path.starts_with("../")
    {
        return Err(RepoNameError::UnresolvedPath);
    }
    if path.starts_with('/') {
        return Err(RepoNameError::AbsolutePath);
    }
    if !path.ends_with(".git") {
        return Err(RepoNameError::MissingGitSuffix);
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum ParseCmdlineError {
    UnknownOperation(ParseOperationError),
    InvalidRepoName(RepoNameError),
    UnexpectedArgCount(ArgCountError),
}

impl From<RepoNameError> for ParseCmdlineError {
    fn from(value: RepoNameError) -> Self {
        Self::InvalidRepoName(value)
    }
}

impl From<ParseOperationError> for ParseCmdlineError {
    fn from(value: ParseOperationError) -> Self {
        Self::UnknownOperation(value)
    }
}

impl From<ArgCountError> for ParseCmdlineError {
    fn from(value: ArgCountError) -> Self {
        Self::UnexpectedArgCount(value)
    }
}

impl fmt::Display for ParseCmdlineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::UnknownOperation(e) => write!(f, "unknown operation: {e}"),
            Self::InvalidRepoName(e) => write!(f, "invalid repository name: {e}"),
            Self::UnexpectedArgCount(e) => e.fmt(f),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
struct ArgCountError {
    provided: usize,
    expected: usize,
}

impl fmt::Display for ArgCountError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "got {} argument(s), expected {}",
            self.provided, self.expected
        )
    }
}

fn get_cmdline_args<const N: usize>() -> Result<[String; N], ArgCountError> {
    let args = std::env::args();
    if args.len() - 1 != N {
        return Err(ArgCountError {
            provided: args.len() - 1,
            expected: N,
        });
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

fn parse_cmdline() -> Result<(String, Operation), ParseCmdlineError> {
    let [repo_path, op_str] = get_cmdline_args::<2>()?;
    let op: Operation = op_str.parse()?;
    validate_repo_path(&repo_path)?;
    Ok((repo_path.to_string(), op))
}

fn repo_exists(name: &str) -> bool {
    match std::fs::metadata(name) {
        Ok(metadata) => metadata.is_dir(),
        _ => false,
    }
}

struct Config {
    href_base: String,
    key_path: String,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum LoadConfigError {
    BaseUrlMissing,
    BaseUrlSlashSuffixMissing,
    KeyPathMissing,
}

impl fmt::Display for LoadConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseUrlMissing => write!(f, "base URL not provided"),
            Self::BaseUrlSlashSuffixMissing => write!(f, "base URL does not end with slash"),
            Self::KeyPathMissing => write!(f, "key path not provided"),
        }
    }
}

fn load_config() -> Result<Config, LoadConfigError> {
    let Ok(href_base) = std::env::var("GITOLFS3_HREF_BASE") else {
        return Err(LoadConfigError::BaseUrlMissing);
    };
    if !href_base.ends_with('/') {
        return Err(LoadConfigError::BaseUrlSlashSuffixMissing);
    }
    let Ok(key_path) = std::env::var("GITOLFS3_KEY_PATH") else {
        return Err(LoadConfigError::KeyPathMissing);
    };
    Ok(Config {
        href_base,
        key_path,
    })
}

fn main() -> ExitCode {
    let config = match load_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load config: {e}");
            return ExitCode::FAILURE;
        }
    };
    let key = match common::load_key(&config.key_path) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to load key: {e}");
            return ExitCode::FAILURE;
        }
    };

    let (repo_name, op) = match parse_cmdline() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {e}\n");
            help();
            // Exit code 2 signifies bad usage of CLI.
            return ExitCode::from(2);
        }
    };

    if !repo_exists(&repo_name) {
        eprintln!("Error: repository does not exist");
        return ExitCode::FAILURE;
    }

    let expires_in = Duration::from_secs(5 * 60);
    let expires_at = Utc::now() + expires_in;

    let Some(tag) = common::generate_tag(
        common::Claims {
            auth_type: common::AuthType::GitLfsAuthenticate,
            repo_path: &repo_name,
            expires_at,
            operation: op,
        },
        key,
    ) else {
        eprintln!("Failed to generate validation tag");
        return ExitCode::FAILURE;
    };

    println!(
        "{{\"header\":{{\"Authorization\":\"Gitolfs3-Hmac-Sha256 {tag}\"}},\
        \"expires_at\":\"{}\",\"href\":\"{}{}/info/lfs?p=1&te={}\"}}",
        common::EscJsonFmt(&expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        common::EscJsonFmt(&config.href_base),
        common::EscJsonFmt(&repo_name),
        expires_at.timestamp()
    );

    ExitCode::SUCCESS
}
