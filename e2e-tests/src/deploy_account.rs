use std::sync::Arc;

use anyhow::Result;
use rstest::*;
use starknet::{
    accounts::{Account, AccountFactory, OpenZeppelinAccountFactory},
    core::types::{BlockId, BlockTag, ExecutionResult, Felt},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::{LocalWallet, SigningKey},
};
use units_utils::starknet::StarknetProvider;
use url::Url;

use units_tests_utils::{
    madara::{madara_node, MadaraRunner},
    starknet::{deploy_dummy_account},
};

#[tokio::test]
#[rstest]
async fn test_deploy_account_works(
    #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
) -> Result<()> {
    let (_runner, provider) = madara_node.await;

    // Deploy a dummy account and asserts on receipt
    let wallet = deploy_dummy_account(provider.clone()).await?;

    let nonce = provider
        .get_nonce(BlockId::Tag(BlockTag::Pending), wallet.address())
        .await
        .unwrap();
    assert_eq!(nonce, Felt::ONE);

    Ok(())
}
