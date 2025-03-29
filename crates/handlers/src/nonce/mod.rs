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
    #[error("Starknet error: {0}")]
    StarknetError(#[from] ProviderError),
}

impl From<NonceError> for ProviderError {
    fn from(value: NonceError) -> Self {
        match value {
            NonceError::StarknetError(error) => error,
            _ => ProviderError::StarknetError(StarknetError::UnexpectedError(value.to_string())),
        }
    }
}

pub async fn get_nonce(
    global_ctx: Arc<GlobalContext>,
    block_id: BlockId,
    address: Felt,
    can_read_nonce_simulation: Option<BroadcastedInvokeTransaction>,
) -> Result<Felt, NonceError> {
    let starknet_provider = global_ctx.starknet_provider();

    // Get contract ABI to check for `can_read_nonce` method
    let has_selector = contract_address_has_selector(
        starknet_provider.clone(),
        address,
        block_id,
        CAN_READ_NONCE_SELECTOR,
    )
    .await
    .map_err(NonceError::StarknetError)?;

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
                    .get(2)
                    .ok_or(NonceError::EmptyCanGetNonceReadResult)?;
                if can_read != &Felt::ONE {
                    Err(NonceError::NonceReadNotAllowed)?
                }
            }
            ExecuteInvocation::Reverted(_) => Err(NonceError::NonceReadNotAllowed)?,
        }
    }

    Ok(starknet_provider.get_nonce(block_id, address).await?)
}

#[cfg(test)]
mod tests {
    use std::future;

    use super::*;
    use assert_matches::assert_matches;
    use rstest::*;
    use starknet::{
        accounts::{Account, ConnectedAccount, ExecutionEncoder, RawExecutionV3},
        core::types::{
            contract::CompiledClass, BlockTag, BroadcastedInvokeTransactionV1, Call, ContractClass,
            FlattenedSierraClass, InvokeTransactionV1,
        },
    };
    use units_tests_utils::{
        madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
        scarb::{scarb_build, ArtifactsMap},
    };
    use units_utils::starknet::{
        declare_contract, StarknetProvider, StarknetWallet, WaitForReceipt,
    };

    #[rstest]
    #[tokio::test]
    async fn test_can_read_nonce_does_not_exist(
        #[future]
        #[with("src/nonce/test_contracts")]
        scarb_build: ArtifactsMap,
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let account = accounts_with_private_key[0].account.clone();

        let mut artifacts = scarb_build.await;
        let artifact_without_can_read_nonce =
            artifacts.remove("ContractWithoutCanReadNonce").unwrap();
        let address = artifact_without_can_read_nonce
            .declare_and_deploy_and_wait_for_receipt(account, vec![], Felt::ZERO, false)
            .await;

        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider));
        let nonce = get_nonce(global_ctx, BlockId::Tag(BlockTag::Pending), address, None)
            .await
            .unwrap();
        assert_eq!(nonce, Felt::ZERO);
    }

    #[rstest]
    #[tokio::test]
    async fn test_can_read_nonce_returns_without_simulation(
        #[future]
        #[with("src/nonce/test_contracts")]
        scarb_build: ArtifactsMap,
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let account = accounts_with_private_key[0].account.clone();

        let mut artifacts = scarb_build.await;
        let artifact_without_can_read_nonce =
            artifacts.remove("ContractWithCanReadNonceFalse").unwrap();
        let address = artifact_without_can_read_nonce
            .declare_and_deploy_and_wait_for_receipt(account, vec![], Felt::ZERO, false)
            .await;

        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider));
        let nonce = get_nonce(global_ctx, BlockId::Tag(BlockTag::Pending), address, None).await;
        assert_matches!(nonce, Err(NonceError::NonceReadSimulationNotProvided));
    }

    #[rstest]
    #[tokio::test]
    async fn test_can_read_nonce_returns_false(
        #[future]
        #[with("src/nonce/test_contracts")]
        scarb_build: ArtifactsMap,
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let account_with_private_key = &accounts_with_private_key[0];

        let mut artifacts = scarb_build.await;
        let artifact_without_can_read_nonce =
            artifacts.remove("ContractWithCanReadNonceFalse").unwrap();
        let address = artifact_without_can_read_nonce
            .declare_and_deploy_and_wait_for_receipt(
                account_with_private_key.account.clone(),
                vec![],
                Felt::ZERO,
                false,
            )
            .await;

        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider));
        let can_read_nonce_simulation = account_with_private_key
            .build_invoke_simulate_transaction(
                vec![Call {
                    to: address,
                    selector: CAN_READ_NONCE_SELECTOR,
                    calldata: vec![],
                }],
                false,
                true,
            )
            .await
            .unwrap();

        let nonce = get_nonce(
            global_ctx,
            BlockId::Tag(BlockTag::Pending),
            address,
            Some(BroadcastedInvokeTransaction::V3(can_read_nonce_simulation)),
        )
        .await;
        assert_matches!(nonce, Err(NonceError::NonceReadNotAllowed));
    }

    #[rstest]
    #[tokio::test]
    async fn test_can_read_nonce_only_owner(
        #[future]
        #[with("src/nonce/test_contracts")]
        scarb_build: ArtifactsMap,
        #[future]
        #[with(2)]
        madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let owner_account_with_private_key = &accounts_with_private_key[0];

        let mut artifacts = scarb_build.await;
        let artifact_without_can_read_nonce = artifacts
            .remove("ContractWithCanReadNonceOnlyOwner")
            .unwrap();
        let contract_address = artifact_without_can_read_nonce
            .declare_and_deploy_and_wait_for_receipt(
                owner_account_with_private_key.account.clone(),
                vec![],
                Felt::ZERO,
                false,
            )
            .await;

        let call = Call {
            to: contract_address,
            selector: CAN_READ_NONCE_SELECTOR,
            calldata: vec![],
        };

        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider));

        // Nonce with owner account should work
        let can_read_nonce_simulation = owner_account_with_private_key
            .build_invoke_simulate_transaction(vec![call.clone()], false, true)
            .await
            .unwrap();
        let nonce = get_nonce(
            global_ctx.clone(),
            BlockId::Tag(BlockTag::Pending),
            contract_address,
            Some(BroadcastedInvokeTransaction::V3(can_read_nonce_simulation)),
        )
        .await
        .unwrap();
        assert_eq!(nonce, Felt::ZERO);

        // Nonce with other account should not work
        let other_account_with_private_key = &accounts_with_private_key[1];
        let can_read_nonce_simulation = other_account_with_private_key
            .build_invoke_simulate_transaction(vec![call], false, true)
            .await
            .unwrap();
        let nonce = get_nonce(
            global_ctx,
            BlockId::Tag(BlockTag::Pending),
            contract_address,
            Some(BroadcastedInvokeTransaction::V3(can_read_nonce_simulation)),
        )
        .await;
        assert_matches!(nonce, Err(NonceError::NonceReadNotAllowed));
    }
}
