use std::sync::Arc;

use starknet::core::types::{
    BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV3, DeclareTransactionResult,
};
use starknet::providers::{Provider, ProviderError};
use units_utils::context::GlobalContext;

pub async fn add_declare_class_transaction(
    global_ctx: Arc<GlobalContext>,
    declare_class_transaction: BroadcastedDeclareTransactionV3,
) -> Result<DeclareTransactionResult, ProviderError> {
    let starknet_provider = global_ctx.starknet_provider();
    starknet_provider
        .add_declare_transaction(BroadcastedDeclareTransaction::V3(declare_class_transaction))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use starknet::{
        accounts::Account,
        core::types::{
            BlockId, BlockTag, BroadcastedDeclareTransactionV3, ContractClass,
            DataAvailabilityMode, ResourceBounds, ResourceBoundsMapping,
        },
        providers::Provider,
    };
    use units_tests_utils::{
        madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
        scarb::{scarb_build, ArtifactsMap},
    };
    use units_utils::starknet::{StarknetProvider, WaitForReceipt};

    #[rstest]
    #[tokio::test]
    async fn test_declare_class(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
        #[future]
        #[with("src/declare_class/test_contracts")]
        scarb_build: ArtifactsMap,
    ) {
        let (_runner, provider, accounts) = madara_node_with_accounts.await;
        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider.clone()));

        // Get the contract artifacts
        let artifacts = scarb_build.await;
        let test_contract = artifacts.get("EmptyContract").unwrap();

        // Sign the declare transaction
        let nonce = provider
            .get_nonce(
                BlockId::Tag(BlockTag::Pending),
                accounts[0].account.address(),
            )
            .await
            .unwrap();
        let declare_tx = accounts[0]
            .account
            .declare_v3(
                Arc::new(test_contract.contract_class.clone().flatten().unwrap()),
                test_contract.compiled_class_hash,
            )
            .gas(0)
            .gas_price(0)
            .nonce(nonce)
            .prepared()
            .unwrap();
        let tx_hash = declare_tx.transaction_hash(false);
        let signature = accounts[0].sign_message(&tx_hash);

        let declare_txn = BroadcastedDeclareTransactionV3 {
            contract_class: Arc::new(test_contract.contract_class.clone().flatten().unwrap()),
            compiled_class_hash: test_contract.compiled_class_hash,
            sender_address: accounts[0].account.address(),
            nonce,
            signature: vec![signature.r, signature.s],
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

        // Declare the class
        let result = add_declare_class_transaction(global_ctx.clone(), declare_txn)
            .await
            .unwrap();
        result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Verify the class was declared by retrieving it
        let declared_class = provider
            .get_class(BlockId::Tag(BlockTag::Pending), result.class_hash)
            .await
            .unwrap();

        match declared_class {
            ContractClass::Sierra(class) => {
                assert_eq!(
                    class.sierra_program,
                    test_contract.contract_class.sierra_program
                );
                assert_eq!(
                    class.contract_class_version,
                    test_contract.contract_class.contract_class_version
                );
            }
            _ => panic!("Expected Sierra class"),
        }
    }
}
