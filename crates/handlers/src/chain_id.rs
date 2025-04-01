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
