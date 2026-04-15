use anyhow::{Context, Result};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::process::Command;

use super::{BoxedStream, Connector};
use crate::address::AddressElement;

#[derive(Debug, Clone)]
pub struct ExecConfig {
    pub filename: String,
    pub arguments: Vec<String>,
}

/// Split a command string respecting quotes, similar to shell splitting.
/// Matches the C# `CommandLineStringSplitter` behavior.
fn split_command_line(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quote: Option<char> = None;

    for ch in input.chars() {
        match in_quote {
            Some(q) if ch == q => {
                in_quote = None;
            }
            Some(_) => {
                current.push(ch);
            }
            None if ch == '"' || ch == '\'' => {
                in_quote = Some(ch);
            }
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            None => {
                current.push(ch);
            }
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

pub fn try_parse_exec(elem: &AddressElement) -> Option<ExecConfig> {
    if !elem.tag.eq_ignore_ascii_case("EXEC") {
        return None;
    }

    let parts = split_command_line(&elem.address);
    if parts.is_empty() {
        return None;
    }

    Some(ExecConfig {
        filename: parts[0].clone(),
        arguments: parts[1..].to_vec(),
    })
}

/// Wrapper around a child process's stdin/stdout.
struct ChildPair {
    child: tokio::process::Child,
    stdout: tokio::process::ChildStdout,
    stdin: tokio::process::ChildStdin,
}

impl AsyncRead for ChildPair {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChildPair {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

impl Drop for ChildPair {
    fn drop(&mut self) {
        // Kill the child process on drop (matches C# behavior)
        let _ = self.child.start_kill();
    }
}

pub struct ExecConnector(pub ExecConfig);

#[async_trait::async_trait]
impl Connector for ExecConnector {
    async fn connect(&self) -> Result<BoxedStream> {
        let mut child = Command::new(&self.0.filename)
            .args(&self.0.arguments)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to spawn {:?}", self.0.filename))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to capture stdout of child process"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to capture stdin of child process"))?;

        Ok(Box::new(ChildPair {
            child,
            stdout,
            stdin,
        }))
    }
}

pub fn try_parse_strategy(elem: &AddressElement) -> Option<ExecConnector> {
    try_parse_exec(elem).map(ExecConnector)
}

pub fn try_parse_factory(elem: &AddressElement) -> Option<ExecConnector> {
    try_parse_exec(elem).map(ExecConnector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exec() {
        let elem = AddressElement::try_parse("EXEC:C:\\Windows\\system32\\cmd.exe").unwrap();
        let config = try_parse_exec(&elem).unwrap();
        assert_eq!(config.filename, "C:\\Windows\\system32\\cmd.exe");
        assert!(config.arguments.is_empty());
    }

    #[test]
    fn parse_exec_with_args() {
        let elem =
            AddressElement::try_parse("EXEC:'C:\\Program Files\\foo.exe' --flag arg").unwrap();
        let config = try_parse_exec(&elem).unwrap();
        assert_eq!(config.filename, "C:\\Program Files\\foo.exe");
        assert_eq!(config.arguments, vec!["--flag", "arg"]);
    }

    #[test]
    fn reject_non_exec() {
        let elem = AddressElement::try_parse("TCP:127.0.0.1:80").unwrap();
        assert!(try_parse_exec(&elem).is_none());
    }
}
