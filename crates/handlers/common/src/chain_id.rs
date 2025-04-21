use std::sync::Arc;

use units_primitives::{
    context::GlobalContext,
    rpc::{GetChainIdResult, HexBytes32},
};

#[derive(Debug, thiserror::Error)]
pub enum ChainIdError {
    #[error("Failed to get chain id: {0}")]
    FailedToGetChainId(String),
}

pub async fn chain_id(global_ctx: Arc<GlobalContext>) -> Result<GetChainIdResult, ChainIdError> {
    let chain_id = global_ctx
        .handler()
        .get_chain_id()
        .await
        .map_err(|e| ChainIdError::FailedToGetChainId(e.to_string()))?;
    Ok(GetChainIdResult {
        chain_id: chain_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StarknetProvider, StarknetWallet};
    use rstest::*;
    use units_tests_utils::{
        madara::{madara_node, MadaraRunner},
        starknet::TestDefault,
    };

    #[rstest]
    #[tokio::test]
    async fn test_chain_id(#[future] madara_node: (MadaraRunner, Arc<StarknetProvider>)) {
        let (_madara_runner, starknet_provider) = madara_node.await;
        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            starknet_provider,
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let chain_id = chain_id(starknet_ctx).await.unwrap();
        assert_eq!(
            chain_id,
            Felt::from_hex_unchecked(&hex::encode("MADARA_DEVNET"))
        );
    }
}
