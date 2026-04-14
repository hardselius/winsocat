use std::collections::HashMap;

/// Parsed address element: `TAG:address,option1=value1,option2=value2`
#[derive(Debug, Clone)]
pub struct AddressElement {
    pub tag: String,
    pub address: String,
    pub options: HashMap<String, String>,
}

impl AddressElement {
    /// Parse an address string. Returns `None` on malformed quoted input.
    pub fn try_parse(input: &str) -> Option<AddressElement> {
        // Split on first ':'
        if let Some((tag, rest)) = input.split_once(':') {
            let sep_offset = get_address_sep_offset(rest)?;
            let address = rest[..sep_offset].trim().to_string();
            let options = get_options(&rest[sep_offset..]);
            Some(AddressElement {
                tag: tag.to_string(),
                address,
                options,
            })
        } else {
            // No colon — split on first ','
            if let Some((tag, rest)) = input.split_once(',') {
                let options = get_options(&format!(",{rest}"));
                Some(AddressElement {
                    tag: tag.to_string(),
                    address: String::new(),
                    options,
                })
            } else {
                Some(AddressElement {
                    tag: input.to_string(),
                    address: String::new(),
                    options: HashMap::new(),
                })
            }
        }
    }
}

/// Find the offset of the first unquoted comma, or the end of string.
/// Returns `None` if quotes are mismatched.
fn get_address_sep_offset(input: &str) -> Option<usize> {
    let mut stack: Vec<char> = Vec::new();

    for (i, ch) in input.char_indices() {
        if ch == ',' && stack.is_empty() {
            return Some(i);
        }
        if ch == '\'' || ch == '"' {
            if stack.is_empty() {
                stack.push(ch);
            } else if *stack.last().unwrap() == ch {
                stack.pop();
            } else {
                stack.push(ch);
            }
        }
    }

    if !stack.is_empty() {
        return None;
    }

    Some(input.len())
}

/// Parse comma-separated `key=value` options.
fn get_options(input: &str) -> HashMap<String, String> {
    let mut options = HashMap::new();

    for part in input.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            options.insert(key.to_string(), value.trim().to_string());
        } else {
            options.insert(trimmed.to_string(), String::new());
        }
    }

    options
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_inputs() {
        let cases = [
            "tag",
            "tag:address",
            "tag,opt1, opt2",
            "tag:address,opt1,opt2",
            "tag:'foo bar'",
            "tag:\"foo bar\",opt1,opt2",
            "tag:'foo \"bar\"',opt1,opt2",
        ];
        for input in cases {
            assert!(
                AddressElement::try_parse(input).is_some(),
                "should parse: {input}"
            );
        }
    }

    #[test]
    fn invalid_inputs() {
        let cases = ["tag:'foo\"", "tag:\"foo bar'", "tag:'foo \"bar',opt1, opt2"];
        for input in cases {
            assert!(
                AddressElement::try_parse(input).is_none(),
                "should fail: {input}"
            );
        }
    }

    #[test]
    fn tag_parsing() {
        let cases = [
            ("STDIO", "STDIO"),
            ("TCP:localhost:80", "TCP"),
            ("TCP-LISTEN:127.0.0.1:80", "TCP-LISTEN"),
            ("NPIPE::fooPipe", "NPIPE"),
            ("EXEC:C:\\foo.exe", "EXEC"),
            (
                "WSL:'echo \"Hello World\"',distribution=Ubuntu,user=root",
                "WSL",
            ),
        ];
        for (input, expected) in cases {
            let elem = AddressElement::try_parse(input).unwrap();
            assert_eq!(elem.tag, expected, "tag mismatch for {input}");
        }
    }

    #[test]
    fn address_parsing() {
        let cases = [
            ("STDIO", ""),
            ("TCP:localhost:80", "localhost:80"),
            ("TCP-LISTEN:127.0.0.1:80", "127.0.0.1:80"),
            ("NPIPE::fooPipe", ":fooPipe"),
            ("EXEC:C:\\foo.exe", "C:\\foo.exe"),
            (
                "WSL:'echo \"Hello World\"',distribution=Ubuntu,user=root",
                "'echo \"Hello World\"'",
            ),
        ];
        for (input, expected) in cases {
            let elem = AddressElement::try_parse(input).unwrap();
            assert_eq!(elem.address, expected, "address mismatch for {input}");
        }
    }
}
