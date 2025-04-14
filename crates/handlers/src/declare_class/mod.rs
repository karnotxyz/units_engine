use std::sync::Arc;

use starknet::accounts::Account;
use starknet::core::types::{
    BlockId, BlockTag, BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV3, Call,
    StarknetError,
};
use starknet::macros::selector;
use starknet::providers::{Provider, ProviderError};
use units_primitives::rpc::DeclareTransactionResult;
use units_primitives::types::ClassVisibility;
use units_utils::context::GlobalContext;
use units_utils::starknet::{WaitForReceipt, WaitForReceiptError};

#[derive(Debug, thiserror::Error)]
pub enum AddDeclareClassTransactionError {
    #[error("Starknet error")]
    StarknetError(#[from] ProviderError),
    #[error("Error waiting for receipt: {0}")]
    WaitForReceiptError(#[from] WaitForReceiptError),
    #[error("Error setting ACL")]
    ErrorSettingAcl,
}

impl From<AddDeclareClassTransactionError> for ProviderError {
    fn from(value: AddDeclareClassTransactionError) -> Self {
        match value {
            AddDeclareClassTransactionError::StarknetError(error) => error,
            _ => ProviderError::StarknetError(StarknetError::UnexpectedError(value.to_string())),
        }
    }
}

pub async fn add_declare_class_transaction(
    global_ctx: Arc<GlobalContext>,
    declare_class_transaction: BroadcastedDeclareTransactionV3,
    visibility: ClassVisibility,
) -> Result<DeclareTransactionResult, AddDeclareClassTransactionError> {
    let starknet_provider = global_ctx.starknet_provider();

    // Check if class exists already
    let class_hash = declare_class_transaction.contract_class.class_hash();
    let class_exists = match starknet_provider
        .get_class(BlockId::Tag(BlockTag::Pending), class_hash)
        .await
    {
        Ok(_) => true,
        Err(err) => match err {
            ProviderError::StarknetError(
                starknet::core::types::StarknetError::ClassHashNotFound,
            ) => false,
            _ => return Err(AddDeclareClassTransactionError::StarknetError(err)),
        },
    };

    if class_exists {
        // Set the ACL before declaring. This is a hacky fix, the ideal
        // solution might be to have an indexer sync the chain and set ACLs
        // after we know a declaration has been made OR to add atomicity in Madara
        // for declare and invoke transactions.
        global_ctx
            .owner_wallet()
            .execute_v3(vec![Call {
                to: global_ctx.declare_acl_address(),
                selector: selector!("set_visibility"),
                calldata: vec![
                    class_hash,
                    visibility.into(),
                    declare_class_transaction.sender_address,
                ],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .map_err(|_| AddDeclareClassTransactionError::ErrorSettingAcl)?
            .wait_for_receipt(starknet_provider.clone(), None)
            .await?;

        return Ok(DeclareTransactionResult {
            class_hash: class_hash.to_hex_string(),
            transaction_hash: None,
            acl_updated: true,
        });
    }

    let declare_result = starknet_provider
        .add_declare_transaction(BroadcastedDeclareTransaction::V3(declare_class_transaction))
        .await?;

    Ok(DeclareTransactionResult {
        class_hash: declare_result.class_hash.to_hex_string(),
        transaction_hash: Some(declare_result.transaction_hash.to_hex_string()),
        acl_updated: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use starknet::{
        accounts::{Account, ConnectedAccount},
        core::types::{
            BlockId, BlockTag, BroadcastedDeclareTransactionV3, DataAvailabilityMode, Felt,
            FunctionCall, ResourceBounds, ResourceBoundsMapping,
        },
        providers::Provider,
    };
    use units_tests_utils::{
        madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
        scarb::{scarb_builds, Artifacts},
        starknet::assert_contract_class_eq,
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
    ) {
        let (_runner, provider, accounts) = madara_node_with_accounts.await;

        // Get the contract artifacts
        let mut artifacts = scarb_builds(vec![
            "src/declare_class/test_contracts",
            "src/get_class/test_contracts",
        ])
        .await;
        let test_contract = artifacts.remove("EmptyContract").unwrap();
        let declare_acl_contract = artifacts.remove("DeclareAclContract").unwrap();
        let declare_acl_address = declare_acl_contract
            .declare_and_deploy_and_wait_for_receipt(
                accounts[0].account.clone(),
                vec![],
                Felt::ZERO,
                false,
            )
            .await;

        // Create a global context with the declare ACL contract address and the account
        let global_ctx = Arc::new(GlobalContext::new_with_provider(
            provider.clone(),
            declare_acl_address,
            accounts[0].account.clone(),
        ));

        // Sign the declare transaction
        let declare_txn = build_declare_txn(accounts[0].clone(), test_contract.clone()).await;

        // Declare the class
        let result = add_declare_class_transaction(
            global_ctx.clone(),
            declare_txn.clone(),
            ClassVisibility::Acl,
        )
        .await
        .unwrap();
        println!("result: {:?}", result);
        let starknet_declare_txn = starknet::core::types::DeclareTransactionResult {
            class_hash: Felt::from_hex_unchecked(result.class_hash.as_str()),
            transaction_hash: Felt::from_hex_unchecked(result.transaction_hash.unwrap().as_str()),
        };
        starknet_declare_txn
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Verify the class was declared by retrieving it
        let declared_class = provider
            .get_class(
                BlockId::Tag(BlockTag::Pending),
                starknet_declare_txn.class_hash,
            )
            .await
            .unwrap();

        assert_contract_class_eq(
            test_contract.contract_class.flatten().unwrap(),
            declared_class,
        );

        // Fetch visibility from the contract
        let visibility = provider
            .call(
                FunctionCall {
                    contract_address: global_ctx.declare_acl_address(),
                    entry_point_selector: selector!("get_visibility"),
                    calldata: vec![starknet_declare_txn.class_hash],
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await
            .unwrap();

        assert_eq!(visibility, vec![ClassVisibility::Acl.into()]);

        // Declare again with new ACL
        let result =
            add_declare_class_transaction(global_ctx.clone(), declare_txn, ClassVisibility::Public)
                .await
                .unwrap();
        assert_eq!(
            result,
            DeclareTransactionResult {
                class_hash: starknet_declare_txn.class_hash.to_hex_string(),
                transaction_hash: None,
                acl_updated: true,
            }
        );

        // Wait for new block number to be sure the ACL transaction is on chain
        let current_block = provider.block_number().await.unwrap();
        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(10);
        let retry_delay = std::time::Duration::from_millis(200);

        loop {
            let block = provider.block_number().await.unwrap();
            if block > current_block {
                break;
            }
            if start_time.elapsed() >= timeout {
                panic!("Block not found after {:?} timeout", timeout);
            }
            tokio::time::sleep(retry_delay).await;
        }

        // Check if ACL was updated
        let visibility = provider
            .call(
                FunctionCall {
                    contract_address: global_ctx.declare_acl_address(),
                    entry_point_selector: selector!("get_visibility"),
                    calldata: vec![starknet_declare_txn.class_hash],
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await
            .unwrap();
        assert_eq!(visibility, vec![ClassVisibility::Public.into()]);
    }

    async fn build_declare_txn(
        account: StarknetWalletWithPrivateKey,
        artifact: Artifacts,
    ) -> BroadcastedDeclareTransactionV3 {
        let provider = account.account.provider();
        let nonce = provider
            .get_nonce(BlockId::Tag(BlockTag::Pending), account.account.address())
            .await
            .unwrap();
        let declare_tx = account
            .account
            .declare_v3(
                Arc::new(artifact.contract_class.clone().flatten().unwrap()),
                artifact.compiled_class_hash,
            )
            .gas(0)
            .gas_price(0)
            .nonce(nonce)
            .prepared()
            .unwrap();
        let tx_hash = declare_tx.transaction_hash(false);
        let signature = account.sign_message(&tx_hash);

        BroadcastedDeclareTransactionV3 {
            contract_class: Arc::new(artifact.contract_class.clone().flatten().unwrap()),
            compiled_class_hash: artifact.compiled_class_hash,
            sender_address: account.account.address(),
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
        }
    }
}
