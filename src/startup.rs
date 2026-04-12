use std::time::Duration;

use tokio::sync::oneshot;

/// Wait for one or more listener startup signals.
///
/// Each signal should be sent only after the listener has successfully bound
/// and is ready to accept traffic.
pub async fn wait_for_start_signals(
    signals: Vec<(String, oneshot::Receiver<()>)>,
    timeout: Duration,
) -> Result<(), anyhow::Error> {
    for (name, rx) in signals {
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Err(anyhow::anyhow!("{} exited before completing startup", name));
            }
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Timed out waiting for {} to complete startup",
                    name
                ));
            }
        }
    }

    Ok(())
}
