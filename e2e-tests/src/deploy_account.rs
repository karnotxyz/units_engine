use std::sync::Arc;

use rstest::*;
use starknet::{
    accounts::Account,
    core::types::{BlockId, BlockTag, Felt},
    providers::Provider,
};
use units_tests_utils::{
    madara::{madara_node, MadaraRunner},
    starknet::deploy_dummy_account,
};
use units_utils::starknet::StarknetProvider;

#[tokio::test]
#[rstest]
async fn test_deploy_account_works(
    #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
) -> anyhow::Result<()> {
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
