use std::sync::Arc;

use crate::tests::utils::{
    madara::{madara_node, MadaraRunner},
    starknet::TestDefault,
};
use crate::{
    tests::utils::starknet::ProviderToDummyGlobalContext, StarknetProvider, StarknetWallet,
};
use rstest::*;
use starknet::core::types::Felt;
use units_handlers_common::chain_id::chain_id;
use units_primitives::rpc::GetChainIdResult;

#[rstest]
#[tokio::test]
async fn test_chain_id(#[future] madara_node: (MadaraRunner, Arc<StarknetProvider>)) {
    let (_madara_runner, starknet_provider) = madara_node.await;
    let global_ctx = starknet_provider.provider_to_dummy_global_context().await;
    let chain_id = chain_id(global_ctx).await.unwrap();
    assert_eq!(
        chain_id,
        GetChainIdResult {
            chain_id: Felt::from_hex_unchecked(&hex::encode("MADARA_DEVNET")).into()
        }
    );
}
