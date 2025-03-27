use std::sync::Arc;

use starknet::{
    core::types::{Felt, TransactionReceipt, TransactionReceiptWithBlockInfo},
    providers::{Provider, ProviderError},
};
use units_utils::context::GlobalContext;

pub async fn get_transaction_receipt(
    global_ctx: Arc<GlobalContext>,
    transaction_hash: Felt,
) -> Result<TransactionReceiptWithBlockInfo, ProviderError> {
    let starknet_provider = global_ctx.starknet_provider();
    // TODO: Check if event is private
    starknet_provider
        .get_transaction_receipt(transaction_hash)
        .await
}

mod tests {
    use super::*;
    use units_tests_utils::madara::MadaraRunner;

    #[tokio::test]
    async fn test_get_transaction_receipt() {
        let madara_runner = MadaraRunner::new().unwrap();
        let rpc_url = madara_runner.rpc_url();
        let global_ctx = GlobalContext::new(rpc_url.unwrap());
    }
}
