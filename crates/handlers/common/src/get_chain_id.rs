use std::sync::Arc;

use serde::Serialize;
use units_primitives::{context::GlobalContext, rpc::GetChainIdResult};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Serialize)]
pub enum GetChainIdError {
    #[error("Failed to get chain id: {0}")]
    FailedToGetChainId(String),
}

pub async fn get_chain_id(
    global_ctx: Arc<GlobalContext>,
) -> Result<GetChainIdResult, GetChainIdError> {
    let chain_id = global_ctx
        .handler()
        .get_chain_id()
        .await
        .map_err(|e| GetChainIdError::FailedToGetChainId(e.to_string()))?;
    Ok(GetChainIdResult { chain_id })
}
