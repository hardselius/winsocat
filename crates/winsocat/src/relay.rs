use anyhow::Result;

use crate::endpoint::AsyncReadWrite;

/// Bidirectional relay between two async streams.
/// Copies data in both directions until either side closes.
pub async fn relay(a: &mut dyn AsyncReadWrite, b: &mut dyn AsyncReadWrite) -> Result<()> {
    tokio::io::copy_bidirectional(a, b).await?;
    Ok(())
}
