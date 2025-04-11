use std::sync::Arc;

use starknet::{
    core::types::Felt,
    providers::{Provider, ProviderError},
};
use units_utils::context::GlobalContext;

pub async fn chain_id(global_ctx: Arc<GlobalContext>) -> Result<Felt, ProviderError> {
    let starknet_provider = global_ctx.starknet_provider();
    starknet_provider.chain_id().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use units_tests_utils::madara::{madara_node, MadaraRunner};
    use units_utils::starknet::StarknetProvider;

    #[rstest]
    #[tokio::test]
    async fn test_chain_id(#[future] madara_node: (MadaraRunner, Arc<StarknetProvider>)) {
        let (_madara_runner, starknet_provider) = madara_node.await;
        let global_ctx = Arc::new(GlobalContext::new_with_provider(starknet_provider));
        let chain_id = chain_id(global_ctx).await.unwrap();
        assert_eq!(
            chain_id,
            Felt::from_hex_unchecked(&hex::encode("MADARA_DEVNET"))
        );
    }
}
