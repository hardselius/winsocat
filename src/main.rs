use std::sync::Arc;

use clap::Parser;

use winsocat::endpoint::{parse_factory, parse_strategy, Strategy};
use winsocat::relay;

#[derive(Parser)]
#[command(name = "winsocat", about = "socat-like relay program")]
struct Cli {
    /// First address (strategy: supports connect and listen modes)
    address1: String,
    /// Second address (factory: connect-only, instantiated per connection)
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
        Strategy::Listen(mut listener) => {
            loop {
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
            }
        }
    }

    Ok(())
}
