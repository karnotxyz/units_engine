use std::sync::Arc;

use anyhow::Result;
use starknet::{
    accounts::{Account, AccountFactory, OpenZeppelinAccountFactory},
    core::types::{BlockId, BlockTag, ExecutionResult, FieldElement},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::{LocalWallet, SigningKey},
};
use url::Url;

use units_tests_utils::{madara::MadaraRunner, starknet::wait_for_receipt, units::UnitsRunner};

#[tokio::test]
async fn test_deploy_account_works() -> Result<()> {
    // Start a Madara node
    let mut runner = UnitsRunner::new()?;
    runner.run().await?;

    // Get the port that Madara is running on
    let rpc_url = runner.rpc_url().unwrap();

    // Create a Starknet provider
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(rpc_url)));

    // Deploy a dummy account and asserts on receipt
    let wallet = units_tests_utils::starknet::deploy_dummy_account(provider.clone()).await?;

    let nonce = provider
        .get_nonce(BlockId::Tag(BlockTag::Pending), wallet.address())
        .await
        .unwrap();
    assert_eq!(nonce, FieldElement::ONE);

    // The runner will be dropped here and Madara will be killed automatically
    Ok(())
}
