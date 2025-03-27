use starknet::{
    accounts::{AccountFactory, ExecutionEncoding, OpenZeppelinAccountFactory, SingleOwnerAccount},
    core::types::{ExecutionResult, FieldElement, MaybePendingTransactionReceipt},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError},
    signers::{LocalWallet, SigningKey},
};
use std::sync::Arc;
use tokio::time::{sleep, Duration, Instant};

const PREDEPLOYED_ACCOUNT_CLASS_HASH: &str =
    "0x00e2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6";

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

pub async fn deploy_dummy_account(
    provider: Arc<JsonRpcClient<HttpTransport>>,
) -> anyhow::Result<Arc<SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, Arc<LocalWallet>>>> {
    let signer = Arc::new(LocalWallet::from(SigningKey::from_secret_scalar(
        FieldElement::ONE,
    )));
    let chain_id = provider.chain_id().await.unwrap();
    let account_factory = OpenZeppelinAccountFactory::new(
        FieldElement::from_hex_be(PREDEPLOYED_ACCOUNT_CLASS_HASH).unwrap(),
        chain_id,
        signer.clone(),
        provider.clone(),
    )
    .await
    .unwrap();

    // Create a deploy account transaction
    let deployment = account_factory
        .deploy(FieldElement::ONE)
        .max_fee(FieldElement::ZERO)
        .send()
        .await
        .unwrap();

    let receipt = wait_for_receipt(provider.clone(), deployment.transaction_hash).await?;

    let account = Arc::new(SingleOwnerAccount::new(
        provider,
        signer,
        deployment.contract_address,
        chain_id,
        ExecutionEncoding::New,
    ));

    assert!(*receipt.execution_result() == ExecutionResult::Succeeded);

    Ok(account)
}
