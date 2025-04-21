use std::sync::Arc;

use units_primitives::context::{ChainHandlerError, GlobalContext};
use units_primitives::rpc::{SendTransactionParams, SendTransactionResult};

#[derive(Debug, thiserror::Error)]
pub enum InvokeTransactionError {
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
}

pub async fn send_transaction(
    global_ctx: Arc<GlobalContext>,
    params: SendTransactionParams,
) -> Result<SendTransactionResult, InvokeTransactionError> {
    let handler = global_ctx.handler();
    handler
        .send_transaction(params)
        .await
        .map_err(InvokeTransactionError::ChainHandlerError)
}
