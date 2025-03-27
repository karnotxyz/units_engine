use starknet::{
    core::types::{FieldElement, MaybePendingTransactionReceipt},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError},
};
use std::sync::Arc;
use tokio::time::{sleep, Duration, Instant};

pub async fn wait_for_receipt(
    provider: Arc<JsonRpcClient<HttpTransport>>,
    txn_hash: FieldElement,
) -> anyhow::Result<MaybePendingTransactionReceipt> {
    let start_time = Instant::now();
    let timeout = Duration::from_secs(10);
    let retry_delay = Duration::from_millis(200);

    loop {
        match provider.get_transaction_receipt(txn_hash).await {
            Ok(receipt) => return Ok(receipt),
            Err(err) => match err {
                ProviderError::StarknetError(
                    starknet::core::types::StarknetError::TransactionHashNotFound,
                ) => {
                    if start_time.elapsed() >= timeout {
                        anyhow::bail!("Transaction not found after 10 seconds timeout");
                    }
                    sleep(retry_delay).await;
                    continue;
                }
                err => return Err(err.into()),
            },
        }
    }
}
