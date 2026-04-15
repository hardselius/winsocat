//! Authentication types for SMB2 session setup.

/// Authentication method for connecting to an SMB2 server.
#[derive(Debug, Clone)]
pub enum Auth {
    /// NTLM authentication with explicit credentials.
    Ntlm {
        username: String,
        password: String,
        domain: String,
    },
    /// Anonymous / guest session (no credentials).
    Anonymous,
}

impl Auth {
    /// Create NTLM auth with the given credentials.
    pub fn ntlm(username: &str, password: &str, domain: &str) -> Self {
        Self::Ntlm {
            username: username.to_owned(),
            password: password.to_owned(),
            domain: domain.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_ntlm_construction() {
        let auth = Auth::ntlm("admin", "secret", "WORKGROUP");
        match &auth {
            Auth::Ntlm {
                username,
                password,
                domain,
            } => {
                assert_eq!(username, "admin");
                assert_eq!(password, "secret");
                assert_eq!(domain, "WORKGROUP");
            }
            Auth::Anonymous => panic!("expected Ntlm"),
        }
    }

    #[test]
    fn auth_anonymous() {
        let auth = Auth::Anonymous;
        assert!(matches!(auth, Auth::Anonymous));
    }
}
