use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 768 * 1024;

#[derive(Debug)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
    pub timed_out: bool,
    pub elapsed: Duration,
}

impl CommandResult {
    pub fn success(&self) -> bool {
        !self.timed_out && self.code == Some(0)
    }
    pub fn error_summary(&self) -> String {
        if self.timed_out { return "timeout".into(); }
        let err = self.stderr.trim();
        if !err.is_empty() {
            err.lines().next().unwrap_or(err).chars().take(240).collect()
        } else {
            format!("exit={:?}", self.code)
        }
    }
}

fn read_to_limit<R: Read>(mut input: R) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 8192];
    let mut out = Vec::new();
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 { break; }
        if out.len() < OUTPUT_LIMIT {
            let keep = (OUTPUT_LIMIT - out.len()).min(n);
            out.extend_from_slice(&buf[..keep]);
        }
    }
    Ok(out)
}

/// Runs a command with concurrent pipe-draining so a large router snapshot cannot deadlock it.
pub fn run(program: &str, args: &[String], input: Option<&[u8]>, timeout: Duration)
    -> io::Result<CommandResult>
{
    let start = Instant::now();
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() { cmd.stdin(Stdio::piped()); }
    else { cmd.stdin(Stdio::null()); }
    let mut child = cmd.spawn()?;
    let out_pipe = child.stdout.take().expect("piped stdout");
    let err_pipe = child.stderr.take().expect("piped stderr");
    let out_task = thread::spawn(move || read_to_limit(out_pipe));
    let err_task = thread::spawn(move || read_to_limit(err_pipe));

    if let Some(data) = input {
        if let Some(mut stdin) = child.stdin.take() {
            // Short, fixed read-only router scripts. Close stdin to end `sh -s`.
            stdin.write_all(data)?;
        }
    }
    let mut timed_out = false;
    let code = loop {
        if let Some(status) = child.try_wait()? {
            break status.code();
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            let status = child.wait()?;
            break status.code();
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = out_task.join().unwrap_or_else(|_| Err(io::Error::other("stdout thread panic")))?;
    let stderr = err_task.join().unwrap_or_else(|_| Err(io::Error::other("stderr thread panic")))?;
    Ok(CommandResult {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        code,
        timed_out,
        elapsed: start.elapsed(),
    })
}

