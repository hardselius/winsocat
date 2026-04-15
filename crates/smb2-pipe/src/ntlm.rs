//! NTLM authentication token generation for SMB2 session setup.
//!
//! This module wraps the `ntlmclient` crate to produce the three NTLM
//! messages used in the SMB2 SESSION_SETUP exchange:
//!
//! 1. **Negotiate** — client sends initial flags + workstation name
//! 2. **Challenge** — server responds with a challenge (parsed here)
//! 3. **Authenticate** — client sends the NTLMv2 response

use anyhow::{bail, Result};

/// Generate the NTLM Negotiate message (Type 1).
///
/// This is the first token sent in the SMB2 SESSION_SETUP request.
pub fn negotiate_token(workstation: &str) -> Result<Vec<u8>> {
    let flags = ntlmclient::Flags::NEGOTIATE_UNICODE
        | ntlmclient::Flags::REQUEST_TARGET
        | ntlmclient::Flags::NEGOTIATE_NTLM
        | ntlmclient::Flags::NEGOTIATE_WORKSTATION_SUPPLIED;

    let msg = ntlmclient::Message::Negotiate(ntlmclient::NegotiateMessage {
        flags,
        supplied_domain: String::new(),
        supplied_workstation: workstation.to_owned(),
        os_version: Default::default(),
    });

    msg.to_bytes()
        .map_err(|e| anyhow::anyhow!("failed to encode NTLM negotiate: {:?}", e))
}

/// Generate the NTLM Authenticate message (Type 3) from the server's
/// challenge (Type 2).
///
/// `challenge_bytes` is the raw NTLM challenge token received from the
/// server in the SESSION_SETUP response.
pub fn authenticate_token(
    challenge_bytes: &[u8],
    username: &str,
    password: &str,
    domain: &str,
    workstation: &str,
) -> Result<Vec<u8>> {
    // Parse the challenge message
    let challenge_msg = ntlmclient::Message::try_from(challenge_bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse NTLM challenge: {:?}", e))?;

    let challenge = match challenge_msg {
        ntlmclient::Message::Challenge(c) => c,
        other => bail!("expected NTLM Challenge message, got: {:?}", other),
    };

    // Collect target info bytes
    let target_info_bytes: Vec<u8> = challenge
        .target_information
        .iter()
        .flat_map(|ie| ie.to_bytes())
        .collect();

    // Build credentials
    let creds = ntlmclient::Credentials {
        username: username.to_owned(),
        password: password.to_owned(),
        domain: domain.to_owned(),
    };

    // Calculate NTLMv2 response
    let response = ntlmclient::respond_challenge_ntlm_v2(
        challenge.challenge,
        &target_info_bytes,
        ntlmclient::get_ntlm_time(),
        &creds,
    );

    // Build the Authenticate message
    let auth_flags = ntlmclient::Flags::NEGOTIATE_UNICODE | ntlmclient::Flags::NEGOTIATE_NTLM;

    let auth_msg = response.to_message(&creds, workstation, auth_flags);

    auth_msg
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("failed to encode NTLM authenticate: {:?}", e))
}

/// Generate an anonymous/guest NTLM Negotiate token.
///
/// For anonymous sessions we still send a negotiate message but with
/// empty credentials in the authenticate phase.
pub fn anonymous_negotiate_token() -> Result<Vec<u8>> {
    negotiate_token("WINSOCAT")
}

/// Generate an anonymous NTLM Authenticate token from the server's challenge.
pub fn anonymous_authenticate_token(challenge_bytes: &[u8]) -> Result<Vec<u8>> {
    authenticate_token(challenge_bytes, "", "", "", "WINSOCAT")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_token_produces_valid_ntlmssp() {
        let token = negotiate_token("TESTPC").unwrap();
        // NTLMSSP signature: "NTLMSSP\0"
        assert!(token.len() >= 8);
        assert_eq!(&token[..8], b"NTLMSSP\0");
        // Type 1 message indicator (byte 8) = 1
        assert_eq!(token[8], 1);
    }

    #[test]
    fn anonymous_negotiate_token_works() {
        let token = anonymous_negotiate_token().unwrap();
        assert_eq!(&token[..8], b"NTLMSSP\0");
        assert_eq!(token[8], 1);
    }
}
