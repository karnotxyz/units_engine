use std::sync::Arc;

use starknet::{
    core::types::{Felt, TransactionReceiptWithBlockInfo},
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

#[cfg(test)]
mod tests {

    use super::*;

    use units_tests_utils::{
        madara::MadaraRunner,
        starknet::{deploy_dummy_account, dummy_transfer},
    };

    #[tokio::test]
    async fn test_get_transaction_receipt_works() {
        let mut madara_runner = MadaraRunner::new().unwrap();
        madara_runner.run().await.unwrap();
        let rpc_url = madara_runner.rpc_url();
        let global_ctx = Arc::new(GlobalContext::new(rpc_url.unwrap()).unwrap());
        let wallet = deploy_dummy_account(global_ctx.starknet_provider())
            .await
            .unwrap();
        let (txn_result, madara_receipt) = dummy_transfer(wallet).await.unwrap();

        let receipt = get_transaction_receipt(global_ctx, txn_result.transaction_hash)
            .await
            .unwrap();

        assert_eq!(receipt, madara_receipt);
    }
}
