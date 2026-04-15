use super::exec::{ExecConfig, ExecConnector};
use crate::address::AddressElement;

const WSL_PATH: &str = "C:\\Windows\\System32\\wsl.exe";

#[derive(Debug, Clone)]
pub struct WslConfig {
    pub command: String,
    pub distribution: Option<String>,
    pub user: Option<String>,
}

pub fn try_parse_wsl(elem: &AddressElement) -> Option<WslConfig> {
    if !elem.tag.eq_ignore_ascii_case("WSL") {
        return None;
    }

    // Check that wsl.exe exists
    if !std::path::Path::new(WSL_PATH).exists() {
        return None;
    }

    let command = elem
        .address
        .trim_matches(|c| c == '\'' || c == '"')
        .to_string();
    let distribution = elem
        .options
        .get("distribution")
        .filter(|s| !s.is_empty())
        .cloned();
    let user = elem.options.get("user").filter(|s| !s.is_empty()).cloned();

    Some(WslConfig {
        command,
        distribution,
        user,
    })
}

fn wsl_to_exec(config: &WslConfig) -> ExecConfig {
    let mut arguments = Vec::new();

    if let Some(ref dist) = config.distribution {
        arguments.push("-d".to_string());
        arguments.push(dist.clone());
    }

    if let Some(ref user) = config.user {
        arguments.push("-u".to_string());
        arguments.push(user.clone());
    }

    arguments.push(config.command.clone());

    ExecConfig {
        filename: WSL_PATH.to_string(),
        arguments,
    }
}

pub fn try_parse_strategy(elem: &AddressElement) -> Option<ExecConnector> {
    try_parse_wsl(elem).map(|c| ExecConnector(wsl_to_exec(&c)))
}

pub fn try_parse_factory(elem: &AddressElement) -> Option<ExecConnector> {
    try_parse_wsl(elem).map(|c| ExecConnector(wsl_to_exec(&c)))
}
