use std::sync::Arc;

use units_primitives::{
    context::{ChainHandler, ChainHandlerError, GlobalContext},
    read_data::{ReadDataError, SignedReadData},
    rpc::{GetTransactionReceiptParams, GetTransactionReceiptResult, HexBytes32, HexBytes32Error},
};

#[derive(Debug, thiserror::Error)]
pub enum TransactionReceiptError {
    #[error("More events than expected")]
    MoreEventsThanExpected,
    #[error("Invalid read signature")]
    InvalidReadSignature,
    #[error("Read Data Error: {0}")]
    ReadSignatureError(#[from] ReadDataError),
    #[error("Invalid transaction type")]
    InvalidTransactionType,
    #[error("Invalid sender address")]
    InvalidSenderAddress,
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
    #[error("HexBytes32 error: {0}")]
    HexBytes32Error(#[from] HexBytes32Error),
}

const CAN_READ_EVENT_FUNCTION_NAME: &str = "can_read_event";

pub async fn get_transaction_receipt(
    global_ctx: Arc<GlobalContext>,
    params: GetTransactionReceiptParams,
) -> Result<GetTransactionReceiptResult, TransactionReceiptError> {
    let handler = global_ctx.handler();

    // Verify signature and ensure it has the required read type
    if !params
        .signed_read_data
        .verify(
            handler.clone(),
            vec![units_primitives::read_data::ReadType::TransactionReceipt {
                transaction_hash: params.transaction_hash.try_into()?,
            }],
        )
        .await?
    {
        return Err(TransactionReceiptError::InvalidReadSignature);
    }

    // Check if reader is the transaction originator
    let raw_txn = handler
        .get_transaction_by_hash(params.transaction_hash)
        .await?;
    let sender_address = raw_txn.sender_address;
    if sender_address
        != params
            .signed_read_data
            .read_data()
            .read_address()
            .clone()
            .into()
    {
        return Err(TransactionReceiptError::InvalidSenderAddress);
    }

    // Get the receipt
    let mut receipt = handler.get_transaction_receipt(params.transaction_hash).await?;

    if receipt.events.is_empty() {
        // If there are no events, we can return the receipt as is
        return Ok(receipt);
    }

    // Fetch events and the contract address from where the event was emitted
    // This is done because we need to call the contract address with the CAN_READ_EVENT_SELECTOR
    // to check if the user has access to read the events
    let mut events = receipt.events;

    let mut can_read_events = Vec::new();
    for event in events.iter() {
        let has_selector = handler
            .contract_has_function(event.from_address, CAN_READ_EVENT_FUNCTION_NAME.to_string())
            .await
            .map_err(ChainHandlerError::from)?;

        let can_read = if has_selector {
            handler
                .simulate_read_access_check(
                    params
                        .signed_read_data
                        .read_data()
                        .read_address()
                        .clone()
                        .into(),
                    event.from_address,
                    CAN_READ_EVENT_FUNCTION_NAME.to_string(),
                    vec![event.keys[0]],
                )
                .await
                .map_err(TransactionReceiptError::ChainHandlerError)?
        } else {
            true
        };
        can_read_events.push(can_read);
    }

    // Filter events based on read permissions
    events = events
        .into_iter()
        .zip(can_read_events)
        .filter_map(|(event, can_read)| if can_read { Some(event) } else { None })
        .collect();

    receipt.events = events;

    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use rstest::*;
    use starknet::accounts::Account;

    use crate::utils::WaitForReceipt;
    use crate::{StarknetProvider, StarknetWallet};
    use starknet::core::types::ExecutionResult;
    #[cfg(feature = "testing")]
    use units_primitives::read_data::{
        sign_read_data, ReadData, ReadDataVersion, ReadType, ReadValidity,
    };
    use units_primitives::read_data::{ReadVerifier, VerifierAccount};
    use units_tests_utils::starknet::TestDefault;
    use units_tests_utils::{
        madara::{
            madara_node, madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey,
        },
        scarb::{scarb_build, ArtifactsMap},
    };

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_get_receipt_fails_with_different_sender(
        #[future]
        #[with("src/transaction_receipt/test_contracts")]
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
        let account1 = accounts_with_private_key[0].account.clone();
        let account2_with_private_key = &accounts_with_private_key[1];

        let mut artifacts = scarb_build.await;
        let artifact = artifacts.remove("ContractWithoutCanReadEvent").unwrap();
        let contract_address = artifact
            .declare_and_deploy_and_wait_for_receipt(account1.clone(), vec![], Felt::ZERO, false)
            .await;

        // Call emit_event from account1
        let result = account1
            .execute_v3(vec![Call {
                to: contract_address,
                selector: selector!("emit_event"),
                calldata: vec![],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .unwrap();
        // Wait for the transaction to be executed
        result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Try to get receipt using account2's signature
        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider.clone(),
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: account2_with_private_key.account.address(),
            }),
            vec![ReadType::TransactionReceipt {
                transaction_hash: result.transaction_hash.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        let signed_read_data = sign_read_data(read_data, account2_with_private_key.private_key)
            .await
            .unwrap();

        let receipt =
            get_transaction_receipt(starknet_ctx, result.transaction_hash, signed_read_data).await;
        assert_matches!(receipt, Err(TransactionReceiptError::InvalidSenderAddress));
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_get_receipt_fails_with_invalid_read_signature(
        #[future]
        #[with("src/transaction_receipt/test_contracts")]
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
        let account1 = accounts_with_private_key[0].account.clone();
        let account2_with_private_key = &accounts_with_private_key[1];

        let mut artifacts = scarb_build.await;
        let artifact = artifacts.remove("ContractWithoutCanReadEvent").unwrap();
        let contract_address = artifact
            .declare_and_deploy_and_wait_for_receipt(account1.clone(), vec![], Felt::ZERO, false)
            .await;

        // Call emit_event from account1
        let result = account1
            .execute_v3(vec![Call {
                to: contract_address,
                selector: selector!("emit_event"),
                calldata: vec![],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .unwrap();
        // Wait for the transaction to be executed
        result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Try to get receipt using an invalid read signature
        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider.clone(),
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: account1.address(),
            }),
            vec![ReadType::TransactionReceipt {
                transaction_hash: result.transaction_hash.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        let signed_read_data = sign_read_data(read_data, account2_with_private_key.private_key)
            .await
            .unwrap();

        let receipt =
            get_transaction_receipt(starknet_ctx, result.transaction_hash, signed_read_data).await;
        assert_matches!(receipt, Err(TransactionReceiptError::InvalidReadSignature));
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    #[ignore]
    async fn test_get_receipt_l1_handler_todo() {
        // TODO: Implement test for L1 handler transaction receipt
        // This requires setting up L1 -> L2 messaging which is complex
        // and not yet supported in the test environment
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_get_receipt_without_can_read_event(
        #[future]
        #[with("src/transaction_receipt/test_contracts")]
        scarb_build: ArtifactsMap,
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        use starknet::core::types::ExecutionResult;

        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let account_with_private_key = &accounts_with_private_key[0];

        let mut artifacts = scarb_build.await;
        let artifact = artifacts.remove("ContractWithoutCanReadEvent").unwrap();
        let contract_address = artifact
            .declare_and_deploy_and_wait_for_receipt(
                account_with_private_key.account.clone(),
                vec![],
                Felt::ZERO,
                false,
            )
            .await;

        // Call emit_event to generate a transaction
        let result = account_with_private_key
            .account
            .execute_v3(vec![Call {
                to: contract_address,
                selector: selector!("emit_event"),
                calldata: vec![],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .unwrap();
        // Wait for the transaction to be executed
        result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Get receipt with proper signature
        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider.clone(),
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::TransactionReceipt {
                transaction_hash: result.transaction_hash.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let receipt =
            get_transaction_receipt(starknet_ctx, result.transaction_hash, signed_read_data)
                .await
                .unwrap();

        // Since contract doesn't implement can_read_event, receipt should have one event
        assert_matches!(receipt.receipt,
            TransactionReceipt::Invoke(invoke_receipt) => {
                assert_eq!(invoke_receipt.events.len(), 1);
                assert_eq!(invoke_receipt.events[0].data[0], Felt::from(1)); // TestEvent data
                assert_eq!(invoke_receipt.events[0].keys[0], selector!("TestEvent"));
                assert_matches!(invoke_receipt.execution_result, ExecutionResult::Succeeded { .. });
                assert_eq!(invoke_receipt.transaction_hash, result.transaction_hash);
            }
        );
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_get_receipt_with_can_read_event(
        #[future]
        #[with("src/transaction_receipt/test_contracts")]
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
        let artifact = artifacts.remove("ContractWithCanReadEvent").unwrap();
        let contract_address = artifact
            .declare_and_deploy_and_wait_for_receipt(
                account_with_private_key.account.clone(),
                vec![],
                Felt::ZERO,
                false,
            )
            .await;

        // Call emit_event_one to generate a transaction
        let emit_one_result = account_with_private_key
            .account
            .execute_v3(vec![Call {
                to: contract_address,
                selector: selector!("emit_event_one"),
                calldata: vec![],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .unwrap();
        // Wait for the transaction to be executed
        emit_one_result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Get receipt - should have no events since we haven't given permission
        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider.clone(),
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::TransactionReceipt {
                transaction_hash: emit_one_result.transaction_hash.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        let signed_read_data =
            sign_read_data(read_data.clone(), account_with_private_key.private_key)
                .await
                .unwrap();

        let receipt = get_transaction_receipt(
            starknet_ctx.clone(),
            emit_one_result.transaction_hash,
            signed_read_data.clone(),
        )
        .await
        .unwrap();

        assert_matches!(receipt.receipt,
            TransactionReceipt::Invoke(invoke_receipt) => {
                assert_eq!(invoke_receipt.events.len(), 0);
            }
        );

        // Update ACL to allow reading TestEventOne
        let result = account_with_private_key
            .account
            .execute_v3(vec![Call {
                to: contract_address,
                selector: selector!("update_acl"),
                calldata: vec![
                    selector!("TestEventOne"),
                    account_with_private_key.account.address(),
                ],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .unwrap();
        // Wait for the transaction to be executed
        result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Get receipt again - should now have the event
        let receipt = get_transaction_receipt(
            starknet_ctx.clone(),
            emit_one_result.transaction_hash,
            signed_read_data.clone(),
        )
        .await
        .unwrap();

        assert_matches!(receipt.receipt,
            TransactionReceipt::Invoke(invoke_receipt) => {
                assert_eq!(invoke_receipt.events.len(), 1);
                assert_eq!(invoke_receipt.events[0].data[0], Felt::from(1)); // TestEventOne data
                assert_eq!(invoke_receipt.events[0].keys[0], selector!("TestEventOne"));
            }
        );

        // Call emit_event_one_and_two
        let emit_one_and_two_result = account_with_private_key
            .account
            .execute_v3(vec![Call {
                to: contract_address,
                selector: selector!("emit_event_one_and_two"),
                calldata: vec![],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .unwrap();
        // Wait for the transaction to be executed
        emit_one_and_two_result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Create new signed read data with new transaction hash
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::TransactionReceipt {
                transaction_hash: emit_one_and_two_result.transaction_hash.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        let signed_read_data =
            sign_read_data(read_data.clone(), account_with_private_key.private_key)
                .await
                .unwrap();

        // Get receipt - should only have TestEventOne since we only have permission for it
        let receipt = get_transaction_receipt(
            starknet_ctx.clone(),
            emit_one_and_two_result.transaction_hash,
            signed_read_data.clone(),
        )
        .await
        .unwrap();

        assert_matches!(receipt.receipt,
            TransactionReceipt::Invoke(invoke_receipt) => {
                assert_eq!(invoke_receipt.events.len(), 1);
                assert_eq!(invoke_receipt.events[0].data[0], Felt::from(1)); // TestEventOne data
                assert_eq!(invoke_receipt.events[0].keys[0], selector!("TestEventOne"));
            }
        );

        // Update ACL to allow reading TestEventTwo
        let result = account_with_private_key
            .account
            .execute_v3(vec![Call {
                to: contract_address,
                selector: selector!("update_acl"),
                calldata: vec![
                    selector!("TestEventTwo"),
                    account_with_private_key.account.address(),
                ],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .unwrap();
        // Wait for the transaction to be executed
        result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Get receipt again - should now have both events
        let receipt = get_transaction_receipt(
            starknet_ctx.clone(),
            emit_one_and_two_result.transaction_hash,
            signed_read_data.clone(),
        )
        .await
        .unwrap();

        assert_matches!(receipt.receipt,
            TransactionReceipt::Invoke(invoke_receipt) => {
                assert_eq!(invoke_receipt.events.len(), 2);
                assert_eq!(invoke_receipt.events[0].data[0], Felt::from(1)); // TestEventOne data
                assert_eq!(invoke_receipt.events[0].keys[0], selector!("TestEventOne"));
                assert_eq!(invoke_receipt.events[1].data[0], Felt::from(2)); // TestEventTwo data
                assert_eq!(invoke_receipt.events[1].keys[0], selector!("TestEventTwo"));
            }
        );
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_get_receipt_reverted_transaction(
        #[future]
        #[with("src/transaction_receipt/test_contracts")]
        scarb_build: ArtifactsMap,
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        use starknet::core::types::ExecutionResult;

        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let account_with_private_key = &accounts_with_private_key[0];

        let mut artifacts = scarb_build.await;
        let artifact = artifacts.remove("ContractWithoutCanReadEvent").unwrap();
        let contract_address = artifact
            .declare_and_deploy_and_wait_for_receipt(
                account_with_private_key.account.clone(),
                vec![],
                Felt::ZERO,
                false,
            )
            .await;

        // Call panic function to generate a reverted transaction
        let result = account_with_private_key
            .account
            .execute_v3(vec![Call {
                to: contract_address,
                selector: selector!("panic"),
                calldata: vec![],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .unwrap();
        // Wait for the transaction to be executed
        result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Get receipt with proper signature
        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider.clone(),
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::TransactionReceipt {
                transaction_hash: result.transaction_hash.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let receipt =
            get_transaction_receipt(starknet_ctx, result.transaction_hash, signed_read_data)
                .await
                .unwrap();

        // Receipt should have no events since transaction reverted
        assert_matches!(receipt.receipt,
            TransactionReceipt::Invoke(invoke_receipt) => {
                assert_eq!(invoke_receipt.events.len(), 0);
                assert_matches!(invoke_receipt.execution_result, ExecutionResult::Reverted { .. });
            }
        );
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_get_receipt_declare_transaction(
        #[future]
        #[with("src/transaction_receipt/test_contracts")]
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
        let artifact = artifacts.remove("ContractWithoutCanReadEvent").unwrap();

        // Declare the contract
        let (_, declare_result) = artifact
            .declare_and_wait_for_receipt(account_with_private_key.account.clone())
            .await;

        let declare_result =
            declare_result.expect("Should not be None as it's contract isn't already declared");

        // Get receipt with proper signature
        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider.clone(),
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::TransactionReceipt {
                transaction_hash: declare_result.transaction_hash.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let receipt = get_transaction_receipt(
            starknet_ctx,
            declare_result.transaction_hash,
            signed_read_data.clone(),
        )
        .await
        .unwrap();

        // Declare transaction should have no events
        assert_matches!(receipt.receipt,
            TransactionReceipt::Declare(declare_receipt) => {
                assert_eq!(declare_receipt.events.len(), 0);
                assert_matches!(declare_receipt.execution_result, ExecutionResult::Succeeded { .. });
                assert_eq!(declare_receipt.transaction_hash, declare_result.transaction_hash);
            }
        );
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_get_receipt_deploy_account_transaction(
        #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
    ) {
        use crate::utils::deploy_account;
        use units_tests_utils::starknet::PREDEPLOYED_ACCOUNT_CLASS_HASH;

        let (_runner, provider) = madara_node.await;

        let private_key = Felt::ONE;
        let deploy_account_result = deploy_account(
            provider.clone(),
            private_key,
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_CLASS_HASH),
        )
        .await
        .unwrap();

        deploy_account_result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Get receipt with proper signature
        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider.clone(),
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: deploy_account_result.contract_address,
            }),
            vec![ReadType::TransactionReceipt {
                transaction_hash: deploy_account_result.transaction_hash.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        let signed_read_data = sign_read_data(read_data, private_key).await.unwrap();

        let receipt = get_transaction_receipt(
            starknet_ctx,
            deploy_account_result.transaction_hash,
            signed_read_data.clone(),
        )
        .await
        .unwrap();

        // Declare transaction should have no events
        assert_matches!(receipt.receipt,
            TransactionReceipt::DeployAccount(deploy_account_receipt) => {
                assert_eq!(deploy_account_receipt.events.len(), 1);
                // OwnerAdded event
                assert_eq!(deploy_account_receipt.events[0].keys[0], selector!("OwnerAdded"));
            }
        );
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_get_receipt_missing_required_read_type(
        #[future]
        #[with("src/transaction_receipt/test_contracts")]
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
        let artifact = artifacts.remove("ContractWithoutCanReadEvent").unwrap();
        let contract_address = artifact
            .declare_and_deploy_and_wait_for_receipt(
                account_with_private_key.account.clone(),
                vec![],
                Felt::ZERO,
                false,
            )
            .await;

        // Call emit_event
        let result = account_with_private_key
            .account
            .execute_v3(vec![Call {
                to: contract_address,
                selector: selector!("emit_event"),
                calldata: vec![],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .unwrap();

        let tx_hash = result.transaction_hash;
        result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // Create read data with the wrong read type (Nonce instead of TransactionReceipt)
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: Felt::ZERO.into(),
            }], // Wrong read type
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider,
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));

        // Try to get receipt with incorrect read type
        let receipt = get_transaction_receipt(starknet_ctx, tx_hash, signed_read_data).await;
        assert_matches!(
            receipt,
            Err(TransactionReceiptError::ReadSignatureError(
                ReadDataError::MissingRequiredReadTypes
            ))
        );
    }
}
