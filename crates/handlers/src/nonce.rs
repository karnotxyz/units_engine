use std::sync::Arc;

use starknet::{
    core::types::{BlockId, Felt},
    providers::{Provider, ProviderError},
};
use units_utils::context::GlobalContext;

pub async fn get_nonce(
    global_ctx: Arc<GlobalContext>,
    block_id: BlockId,
    address: Felt,
) -> Result<Felt, ProviderError> {
    let starknet_provider = global_ctx.starknet_provider();

    // TODO: Handle privacy checks
    starknet_provider.get_nonce(block_id, address).await
}
