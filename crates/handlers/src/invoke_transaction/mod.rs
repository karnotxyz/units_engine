use std::sync::Arc;

use starknet::core::types::{
    BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV3, InvokeTransactionResult,
};
use starknet::providers::{Provider, ProviderError};
use units_utils::context::GlobalContext;

pub async fn add_invoke_transaction(
    global_ctx: Arc<GlobalContext>,
    invoke_transaction: BroadcastedInvokeTransactionV3,
) -> Result<InvokeTransactionResult, ProviderError> {
    let starknet_provider = global_ctx.starknet_provider();
    starknet_provider
        .add_invoke_transaction(BroadcastedInvokeTransaction::V3(invoke_transaction))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use starknet::{
        accounts::{Account, ExecutionEncoding},
        core::types::{
            BlockId, BlockTag, Call, DataAvailabilityMode, ExecutionResult, Felt, ResourceBounds,
            ResourceBoundsMapping,
        },
        macros::selector,
    };
    use units_tests_utils::{
        madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
        scarb::{scarb_build, ArtifactsMap},
        starknet::TestDefault,
    };
    use units_utils::starknet::{encode_calls, StarknetProvider, StarknetWallet, WaitForReceipt};

    #[rstest]
    #[tokio::test]
    async fn test_add_invoke_transaction(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
        #[future]
        #[with("src/invoke_transaction/test_contracts")]
        scarb_build: ArtifactsMap,
    ) {
        let (_runner, provider, accounts) = madara_node_with_accounts.await;
        let global_ctx = Arc::new(GlobalContext::new_with_provider(
            provider.clone(),
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));

        // Get the contract artifacts
        let mut artifacts = scarb_build.await;
        let test_contract = artifacts.remove("HelloWorldContract").unwrap();

        // Deploy the contract
        let contract_address = test_contract
            .declare_and_deploy_and_wait_for_receipt(
                accounts[0].account.clone(),
                vec![],
                Felt::ONE,
                true,
            )
            .await;

        // Sign the message
        let nonce = provider
            .get_nonce(
                BlockId::Tag(BlockTag::Pending),
                accounts[0].account.address(),
            )
            .await
            .unwrap();
        let calls = vec![Call {
            to: contract_address,
            selector: selector!("hello_world"),
            calldata: vec![],
        }];
        let txn_hash = accounts[0]
            .account
            .execute_v3(calls.clone())
            .gas(0)
            .gas_price(0)
            .nonce(nonce)
            .prepared()
            .unwrap()
            .transaction_hash(false);
        let signature = accounts[0].sign_message(&txn_hash);
        // Invoke the contract
        let invoke_tx = BroadcastedInvokeTransactionV3 {
            sender_address: accounts[0].account.address(),
            calldata: encode_calls(&calls, ExecutionEncoding::New),
            signature: vec![signature.r, signature.s],
            nonce,
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l2_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };
        let invoke_tx_result = add_invoke_transaction(global_ctx, invoke_tx).await.unwrap();
        let receipt = invoke_tx_result
            .wait_for_receipt(provider, None)
            .await
            .unwrap();
        assert_eq!(
            receipt.receipt.execution_result(),
            &ExecutionResult::Succeeded
        );
    }
}
