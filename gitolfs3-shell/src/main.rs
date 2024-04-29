use std::{os::unix::process::CommandExt, process::ExitCode};

fn main() -> ExitCode {
    let bad_usage = ExitCode::from(2);

    let mut args = std::env::args().skip(1);
    if args.next() != Some("-c".to_string()) {
        eprintln!("Expected usage: shell -c <argument>");
        return bad_usage;
    }
    let Some(cmd) = args.next() else {
        eprintln!("Missing argument for argument '-c'");
        return bad_usage;
    };
    if args.next().is_some() {
        eprintln!("Too many arguments passed");
        return bad_usage;
    }

    let Some(mut cmd) = parse_cmd(&cmd) else {
        eprintln!("Bad command");
        return bad_usage;
    };

    let Some(mut program) = cmd.drain(0..1).next() else {
        eprintln!("Bad command");
        return bad_usage;
    };
    if program == "git" {
        let Some(subcommand) = cmd.drain(0..1).next() else {
            eprintln!("Bad command");
            return bad_usage;
        };
        program.push('-');
        program.push_str(&subcommand);
    }

    let mut args = Vec::new();

    let git_cmds = ["git-receive-pack", "git-upload-archive", "git-upload-pack"];
    if git_cmds.contains(&program.as_str()) {
        if cmd.len() != 1 {
            eprintln!("Bad command");
            return bad_usage;
        }
        let repository = cmd[0].trim_start_matches('/');
        args.push(repository);
    } else if program == "git-lfs-authenticate" {
        program.clear();
        program.push_str("gitolfs3-authenticate");
        if cmd.len() != 2 {
            eprintln!("Bad command");
            return bad_usage;
        }
        let repository = cmd[0].trim_start_matches('/');
        args.push(repository);
        args.push(&cmd[1]);
    } else {
        eprintln!("Unknown command");
        return bad_usage;
    }

    let e = std::process::Command::new(program).args(args).exec();
    eprintln!("Error: {e}");
    ExitCode::FAILURE
}

fn parse_cmd(mut cmd: &str) -> Option<Vec<String>> {
    let mut args = Vec::<String>::new();

    cmd = cmd.trim_matches(is_posix_space);
    while !cmd.is_empty() {
        if cmd.starts_with('\'') {
            let (arg, remaining) = parse_sq(cmd)?;
            args.push(arg);
            cmd = remaining.trim_start_matches(is_posix_space);
        } else if let Some((arg, remaining)) = cmd.split_once(is_posix_space) {
            args.push(arg.to_owned());
            cmd = remaining.trim_start_matches(is_posix_space);
        } else {
            args.push(cmd.to_owned());
            cmd = "";
        }
    }

    Some(args)
}

fn is_posix_space(c: char) -> bool {
    // Form feed: 0x0c
    // Vertical tab: 0x0b
    c == ' ' || c == '\x0c' || c == '\n' || c == '\r' || c == '\t' || c == '\x0b'
}

fn parse_sq(s: &str) -> Option<(String, &str)> {
    #[derive(PartialEq, Eq)]
    enum SqState {
        Quoted,
        Unquoted { may_escape: bool },
        UnquotedEscaped,
    }

    let mut result = String::new();
    let mut state = SqState::Unquoted { may_escape: false };
    let mut remaining = "";
    for (i, c) in s.char_indices() {
        match state {
            SqState::Unquoted { may_escape: false } => {
                if c != '\'' {
                    return None;
                }
                state = SqState::Quoted
            }
            SqState::Quoted => {
                if c == '\'' {
                    state = SqState::Unquoted { may_escape: true };
                    continue;
                }
                result.push(c);
            }
            SqState::Unquoted { may_escape: true } => {
                if is_posix_space(c) {
                    remaining = &s[i..];
                    break;
                }
                if c != '\\' {
                    return None;
                }
                state = SqState::UnquotedEscaped;
            }
            SqState::UnquotedEscaped => {
                if c != '\\' && c != '!' {
                    return None;
                }
                result.push(c);
                state = SqState::Unquoted { may_escape: false };
            }
        }
    }

    if state != (SqState::Unquoted { may_escape: true }) {
        return None;
    }
    Some((result, remaining))
}
