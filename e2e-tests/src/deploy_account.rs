use std::sync::Arc;

use anyhow::Result;
use starknet::{
    accounts::{AccountFactory, OpenZeppelinAccountFactory},
    core::types::{ExecutionResult, FieldElement},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::{LocalWallet, SigningKey},
};
use url::Url;

use crate::{devnet::MadaraRunner, utils::starknet::wait_for_receipt};

const PREDEPLOYED_ACCOUNT_CLASS_HASH: &str =
    "0x00e2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6";

#[tokio::test]
async fn test_deploy_account_works() -> Result<()> {
    // Start a Madara node
    let mut runner = MadaraRunner::new()?;
    runner.run().await?;

    // Get the port that Madara is running on
    let port = runner.port().unwrap();

    // Create a Starknet provider
    let rpc_url = format!("http://localhost:{}", port);
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(Url::parse(
        &rpc_url,
    )?)));

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(FieldElement::ONE));
    let chain_id = provider.chain_id().await.unwrap();
    let account_factory = OpenZeppelinAccountFactory::new(
        FieldElement::from_hex_be(PREDEPLOYED_ACCOUNT_CLASS_HASH).unwrap(),
        chain_id,
        signer,
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

    assert!(*receipt.execution_result() == ExecutionResult::Succeeded);

    // The runner will be dropped here and Madara will be killed automatically
    Ok(())
}
