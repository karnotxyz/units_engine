use std::sync::Arc;

use starknet::core::types::{BroadcastedDeployAccountTransaction, DeployAccountTransactionResult};
use starknet::providers::{Provider, ProviderError};
use units_utils::context::GlobalContext;

pub async fn add_deploy_account_transaction(
    global_ctx: Arc<GlobalContext>,
    deploy_account_transaction: BroadcastedDeployAccountTransaction,
) -> Result<DeployAccountTransactionResult, ProviderError> {
    let starknet_provider = global_ctx.starknet_provider();
    starknet_provider
        .add_deploy_account_transaction(deploy_account_transaction)
        .await
}
