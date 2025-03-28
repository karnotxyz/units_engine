use std::sync::Arc;

use starknet::{
    core::types::{
        BlockId, BroadcastedInvokeTransaction, BroadcastedTransaction, ExecuteInvocation, Felt,
        SimulationFlag, StarknetError,
    },
    macros::selector,
    providers::{Provider, ProviderError},
};
use units_utils::{
    context::GlobalContext,
    starknet::{contract_address_has_selector, GetExecutionResult},
};

const CAN_READ_NONCE_SELECTOR: Felt = selector!("can_read_nonce");

#[derive(Debug, thiserror::Error)]
pub enum NonceError {
    #[error("No can read nonce simulation provided")]
    NonceReadSimulationNotProvided,
    #[error("Failed to read execution result")]
    FailedExecutionResultRead(anyhow::Error),
    #[error("Empty can get nonce read result")]
    EmptyCanGetNonceReadResult,
    #[error("Nonce read not allowed")]
    NonceReadNotAllowed,
}

impl From<NonceError> for ProviderError {
    fn from(value: NonceError) -> Self {
        ProviderError::StarknetError(StarknetError::UnexpectedError(value.to_string()))
    }
}

pub async fn get_nonce(
    global_ctx: Arc<GlobalContext>,
    block_id: BlockId,
    address: Felt,
    can_read_nonce_simulation: Option<BroadcastedInvokeTransaction>,
) -> Result<Felt, ProviderError> {
    let starknet_provider = global_ctx.starknet_provider();

    // Get contract ABI to check for `can_read_nonce` method
    let has_selector = contract_address_has_selector(
        starknet_provider.clone(),
        address,
        block_id,
        CAN_READ_NONCE_SELECTOR,
    )
    .await
    .unwrap();

    if has_selector {
        let can_read_nonce_simulation =
            can_read_nonce_simulation.ok_or(NonceError::NonceReadSimulationNotProvided)?;

        let can_read_nonce = starknet_provider
            .simulate_transaction(
                block_id,
                BroadcastedTransaction::Invoke(can_read_nonce_simulation),
                vec![SimulationFlag::SkipFeeCharge],
            )
            .await?;

        match can_read_nonce
            .get_execution_result()
            .map_err(NonceError::FailedExecutionResultRead)?
        {
            ExecuteInvocation::Success(function_invocation) => {
                let can_read = function_invocation
                    .result
                    .get(0)
                    .ok_or(NonceError::EmptyCanGetNonceReadResult)?;
                if can_read != &Felt::ONE {
                    Err(NonceError::NonceReadNotAllowed)?
                }
            }
            ExecuteInvocation::Reverted(_) => Err(NonceError::NonceReadNotAllowed)?,
        }
    }

    starknet_provider.get_nonce(block_id, address).await
}
