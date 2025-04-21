use std::sync::Arc;

use serde::Serialize;
use units_primitives::{context::GlobalContext, rpc::GetChainIdResult};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Serialize)]
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
    Ok(GetChainIdResult { chain_id })
}
