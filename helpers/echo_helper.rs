/// Minimal stdin-to-stdout copier used as a cross-platform `cat`
/// replacement in EXEC integration tests. Unlike `findstr` on
/// Windows, this doesn't require line-buffered \r\n input.
fn main() {
    let mut buf = [0u8; 4096];
    loop {
        use std::io::Read;
        match std::io::stdin().read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                use std::io::Write;
                std::io::stdout().write_all(&buf[..n]).unwrap();
                std::io::stdout().flush().unwrap();
            }
            Err(_) => break,
        }
    }
}
