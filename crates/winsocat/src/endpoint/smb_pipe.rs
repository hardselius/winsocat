//! SMB-PIPE endpoint: connect to a remote named pipe via SMB2.
//!
//! Address format: `SMB-PIPE:<server>:<pipe>,user=...,password=...,domain=...,port=...`
//!
//! Options:
//!   - `user` — username for NTLM authentication (default: anonymous)
//!   - `password` — password (supports `$ENV_VAR` references)
//!   - `domain` — NTLM domain (default: `.`)
//!   - `port` — TCP port (default: 445)

use anyhow::Result;

use super::{BoxedStream, Connector};
use crate::address::AddressElement;
use smb2_pipe::auth::Auth;
use smb2_pipe::client::SmbPipeClient;

/// Default SMB2 port.
const DEFAULT_PORT: u16 = 445;

/// Configuration parsed from an SMB-PIPE address string.
#[derive(Debug, Clone)]
pub struct SmbPipeConfig {
    pub server: String,
    pub pipe: String,
    pub port: u16,
    pub auth: SmbPipeAuth,
}

/// Auth configuration (cloneable, unlike `smb2_pipe::auth::Auth`).
#[derive(Debug, Clone)]
pub enum SmbPipeAuth {
    Anonymous,
    Ntlm {
        user: String,
        password: String,
        domain: String,
    },
}

impl SmbPipeAuth {
    fn to_auth(&self) -> Auth {
        match self {
            SmbPipeAuth::Anonymous => Auth::Anonymous,
            SmbPipeAuth::Ntlm {
                user,
                password,
                domain,
            } => Auth::Ntlm {
                username: user.clone(),
                password: password.clone(),
                domain: domain.clone(),
            },
        }
    }
}

/// Resolve a value that may be an environment variable reference (`$VAR`).
///
/// If the value starts with `$`, the remainder is treated as an
/// environment variable name. Returns the variable's value, or an
/// empty string with a warning on stderr if the variable is not set.
/// Non-prefixed values are returned as-is.
fn resolve_env(value: &str) -> String {
    if let Some(var_name) = value.strip_prefix('$') {
        match std::env::var(var_name) {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "warning: environment variable ${var_name} is not set, \
                     using empty string"
                );
                String::new()
            }
        }
    } else {
        value.to_string()
    }
}

/// Try to parse an `AddressElement` as an SMB-PIPE endpoint.
///
/// Format: `SMB-PIPE:server:pipe,user=...,password=...,domain=...,port=...`
pub fn try_parse_smb_pipe(elem: &AddressElement) -> Option<SmbPipeConfig> {
    if !elem.tag.eq_ignore_ascii_case("SMB-PIPE") {
        return None;
    }

    // Address is "server:pipe" — split on first ':'
    let (server, pipe) = elem.address.split_once(':')?;
    if server.is_empty() || pipe.is_empty() {
        return None;
    }

    let port: u16 = elem
        .options
        .get("port")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let auth = if let Some(user) = elem.options.get("user") {
        let password = elem
            .options
            .get("password")
            .map(|v| resolve_env(v))
            .unwrap_or_default();
        let domain = elem
            .options
            .get("domain")
            .cloned()
            .unwrap_or_else(|| ".".to_string());
        SmbPipeAuth::Ntlm {
            user: user.clone(),
            password,
            domain,
        }
    } else {
        SmbPipeAuth::Anonymous
    };

    Some(SmbPipeConfig {
        server: server.to_string(),
        pipe: pipe.to_string(),
        port,
        auth,
    })
}

// --- Connector ---

pub struct SmbPipeConnector(SmbPipeConfig);

#[async_trait::async_trait]
impl Connector for SmbPipeConnector {
    async fn connect(&self) -> Result<BoxedStream> {
        let auth = self.0.auth.to_auth();
        let client =
            SmbPipeClient::connect(&self.0.server, self.0.port, &self.0.pipe, &auth).await?;
        Ok(Box::new(client.stream))
    }
}

// --- Parse entry points ---

pub fn try_parse_connect_strategy(elem: &AddressElement) -> Option<SmbPipeConnector> {
    try_parse_smb_pipe(elem).map(SmbPipeConnector)
}

pub fn try_parse_factory(elem: &AddressElement) -> Option<SmbPipeConnector> {
    try_parse_smb_pipe(elem).map(SmbPipeConnector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_smb_pipe_basic() {
        let elem = AddressElement::try_parse("SMB-PIPE:myserver:mypipe").unwrap();
        let config = try_parse_smb_pipe(&elem).unwrap();
        assert_eq!(config.server, "myserver");
        assert_eq!(config.pipe, "mypipe");
        assert_eq!(config.port, 445);
        assert!(matches!(config.auth, SmbPipeAuth::Anonymous));
    }

    #[test]
    fn parse_smb_pipe_with_auth() {
        let elem = AddressElement::try_parse(
            "SMB-PIPE:myserver:mypipe,user=admin,password=secret,domain=CORP",
        )
        .unwrap();
        let config = try_parse_smb_pipe(&elem).unwrap();
        assert_eq!(config.server, "myserver");
        assert_eq!(config.pipe, "mypipe");
        match &config.auth {
            SmbPipeAuth::Ntlm {
                user,
                password,
                domain,
            } => {
                assert_eq!(user, "admin");
                assert_eq!(password, "secret");
                assert_eq!(domain, "CORP");
            }
            _ => panic!("expected NTLM auth"),
        }
    }

    #[test]
    fn parse_smb_pipe_with_port() {
        let elem = AddressElement::try_parse("SMB-PIPE:myserver:mypipe,port=4450").unwrap();
        let config = try_parse_smb_pipe(&elem).unwrap();
        assert_eq!(config.port, 4450);
    }

    #[test]
    fn parse_smb_pipe_env_password() {
        std::env::set_var("TEST_SMB_PASS", "env_secret");
        let elem = AddressElement::try_parse(
            "SMB-PIPE:myserver:mypipe,user=admin,password=$TEST_SMB_PASS",
        )
        .unwrap();
        let config = try_parse_smb_pipe(&elem).unwrap();
        match &config.auth {
            SmbPipeAuth::Ntlm { password, .. } => {
                assert_eq!(password, "env_secret");
            }
            _ => panic!("expected NTLM auth"),
        }
        std::env::remove_var("TEST_SMB_PASS");
    }

    #[test]
    fn parse_smb_pipe_default_domain() {
        let elem =
            AddressElement::try_parse("SMB-PIPE:myserver:mypipe,user=admin,password=x").unwrap();
        let config = try_parse_smb_pipe(&elem).unwrap();
        match &config.auth {
            SmbPipeAuth::Ntlm { domain, .. } => {
                assert_eq!(domain, ".");
            }
            _ => panic!("expected NTLM auth"),
        }
    }

    #[test]
    fn reject_non_smb_pipe() {
        let elem = AddressElement::try_parse("TCP:127.0.0.1:80").unwrap();
        assert!(try_parse_smb_pipe(&elem).is_none());
    }

    #[test]
    fn reject_missing_pipe_name() {
        let elem = AddressElement::try_parse("SMB-PIPE:myserver").unwrap();
        assert!(try_parse_smb_pipe(&elem).is_none());
    }

    #[test]
    fn reject_empty_server() {
        let elem = AddressElement::try_parse("SMB-PIPE::mypipe").unwrap();
        assert!(try_parse_smb_pipe(&elem).is_none());
    }

    #[test]
    fn case_insensitive_tag() {
        let elem = AddressElement::try_parse("smb-pipe:myserver:mypipe").unwrap();
        assert!(try_parse_smb_pipe(&elem).is_some());
    }

    #[test]
    fn resolve_env_literal_value() {
        assert_eq!(resolve_env("plaintext"), "plaintext");
    }

    #[test]
    fn resolve_env_set_variable() {
        std::env::set_var("TEST_RESOLVE_SET", "found_it");
        assert_eq!(resolve_env("$TEST_RESOLVE_SET"), "found_it");
        std::env::remove_var("TEST_RESOLVE_SET");
    }

    #[test]
    fn resolve_env_unset_variable_returns_empty() {
        // Make sure the variable doesn't exist
        std::env::remove_var("TEST_RESOLVE_UNSET_XYZ");
        let result = resolve_env("$TEST_RESOLVE_UNSET_XYZ");
        assert_eq!(result, "");
    }
}
