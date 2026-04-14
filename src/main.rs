use std::sync::Arc;

use clap::Parser;

use winsocat::endpoint::{parse_factory, parse_strategy, Strategy};
use winsocat::relay;

#[derive(Parser)]
#[command(
    name = "winsocat",
    about = "Socat-like relay for bridging I/O streams",
    after_help = "\
Address format:
  TAG:address,option1=value1,option2=value2

Address types for ADDRESS1 (connect or listen):
  STDIO                       Standard input/output
  TCP:<host>:<port>           TCP connect
  TCP-LISTEN:<host>:<port>    TCP listen
  EXEC:<command>              Child process stdin/stdout
  UNIX:<path>                 Unix socket connect         [unix]
  UNIX-LISTEN:<path>          Unix socket listen          [unix]
  NPIPE:<server>:<pipe>       Named pipe connect          [windows]
  NPIPE-LISTEN:<pipe>         Named pipe listen           [windows]
  HVSOCK:<vmId>:<serviceId>   Hyper-V socket connect      [windows]
  HVSOCK-LISTEN:<serviceId>   Hyper-V socket listen       [windows]
  WSL:<cmd>,distribution=..   WSL process                 [windows]
  SP:<port>,baudrate=...      Serial port

Address types for ADDRESS2 (connect only):
  STDIO, TCP, EXEC, UNIX, NPIPE, HVSOCK, WSL, SP

Examples:
  winsocat TCP-LISTEN:127.0.0.1:8000 STDIO
  winsocat STDIO TCP:127.0.0.1:80
  winsocat TCP-LISTEN:127.0.0.1:9000 EXEC:ls
  winsocat TCP-LISTEN:127.0.0.1:8080 TCP:example.com:80"
)]
struct Cli {
    /// First address (connect or listen mode)
    address1: String,
    /// Second address (connect only, created per connection)
    address2: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let strategy = parse_strategy(&cli.address1)?;
    let factory = Arc::new(parse_factory(&cli.address2)?);

    match strategy {
        Strategy::Connect(connector) => {
            let mut src = connector.connect().await?;
            let mut dst = factory.connect().await?;
            relay::relay(&mut *src, &mut *dst).await?;
        }
        Strategy::Listen(mut listener) => loop {
            let mut src = listener.accept().await?;
            let factory = Arc::clone(&factory);

            tokio::spawn(async move {
                match factory.connect().await {
                    Ok(mut dst) => {
                        let _ = relay::relay(&mut *src, &mut *dst).await;
                    }
                    Err(e) => {
                        eprintln!("factory connect error: {e}");
                    }
                }
            });
        },
    }

    Ok(())
}
