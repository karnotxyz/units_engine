use starknet::core::types::BroadcastedDeployAccountTransaction;
use starknet::providers::Provider;
use units_utils::context::GlobalContext;

pub async fn add_deploy_account_transaction(
    global_ctx: &mut GlobalContext,
    deploy_account_transaction: BroadcastedDeployAccountTransaction,
) -> anyhow::Result<()> {
    let starknet_provider = global_ctx.starknet_provider();
    starknet_provider.add_deploy_account_transaction(deploy_account_transaction).await?;
    Ok(())
}
