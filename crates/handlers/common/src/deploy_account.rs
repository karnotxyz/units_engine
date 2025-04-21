use std::sync::Arc;

use starknet::core::types::{
    BroadcastedDeployAccountTransaction, BroadcastedDeployAccountTransactionV3,
    DeployAccountTransactionResult,
};
use starknet::providers::{Provider, ProviderError};
use units_primitives::context::{ChainHandlerError, GlobalContext};
use units_primitives::rpc::{DeployAccountParams, DeployAccountResult};

#[derive(Debug, thiserror::Error)]
pub enum DeployAccountError {
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
}

pub async fn add_deploy_account_transaction(
    global_ctx: Arc<GlobalContext>,
    deploy_account_transaction: DeployAccountParams,
) -> Result<DeployAccountResult, DeployAccountError> {
    global_ctx
        .handler()
        .deploy_account(deploy_account_transaction)
        .await
        .map_err(DeployAccountError::ChainHandlerError)
}
