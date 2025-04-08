use std::sync::Arc;

use starknet::{
    core::types::{
        BlockId, BlockTag, Call, ExecuteInvocation, Felt, StarknetError, TransactionReceipt,
        TransactionReceiptWithBlockInfo, TransactionTrace,
    },
    macros::selector,
    providers::{Provider, ProviderError},
};
use units_primitives::read_data::{ReadDataError, SignedReadData};
use units_utils::{
    context::GlobalContext,
    starknet::{
        contract_address_has_selector, get_events_from_function_invocation, simulate_boolean_read,
        GetSenderAddress, SimulationError,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum TransactionReceiptError {
    #[error("More events than expected")]
    MoreEventsThanExpected,
    #[error("Starknet error: {0}")]
    StarknetError(#[from] ProviderError),
    #[error("Read signature not provided")]
    ReadSignatureNotProvided,
    #[error("Invalid read signature")]
    InvalidReadSignature,
    #[error("Read Data Error: {0}")]
    ReadSignatureError(#[from] ReadDataError),
    #[error("Invalid transaction type")]
    InvalidTransactionType,
    #[error("Invalid sender address")]
    InvalidSenderAddress,
    #[error("Simulation error: {0}")]
    SimulationError(#[from] SimulationError),
}

impl From<TransactionReceiptError> for ProviderError {
    fn from(value: TransactionReceiptError) -> Self {
        match value {
            TransactionReceiptError::StarknetError(error) => error,
            _ => ProviderError::StarknetError(StarknetError::UnexpectedError(value.to_string())),
        }
    }
}

const CAN_READ_EVENT_SELECTOR: Felt = selector!("can_read_event");

pub async fn get_transaction_receipt(
    global_ctx: Arc<GlobalContext>,
    transaction_hash: Felt,
    signed_read_data: Option<SignedReadData>,
) -> Result<TransactionReceiptWithBlockInfo, TransactionReceiptError> {
    let starknet_provider = global_ctx.starknet_provider();

    let signed_read_data =
        signed_read_data.ok_or(TransactionReceiptError::ReadSignatureNotProvided)?;
    if !signed_read_data.verify(starknet_provider.clone()).await? {
        return Err(TransactionReceiptError::InvalidReadSignature);
    }

    // Check if reader is the transaction originator
    let raw_txn = starknet_provider
        .get_transaction_by_hash(transaction_hash)
        .await?;
    let sender_address = raw_txn
        .get_sender_address()
        .ok_or(TransactionReceiptError::InvalidTransactionType)?;
    if sender_address != *signed_read_data.read_data().contract_address() {
        return Err(TransactionReceiptError::InvalidSenderAddress);
    }

    // Get the receipt
    let mut receipt = starknet_provider
        .get_transaction_receipt(transaction_hash)
        .await?;

    // Fetch events and the contract address from where the event was emitted
    // This is done because we need to call the contract address with the CAN_READ_EVENT_SELECTOR
    // to check if the user has access to read the events
    let mut events = receipt.receipt.events().to_vec();
    if events.is_empty() {
        // If there are no events, we can return the receipt as is
        return Ok(receipt);
    }
    // Events don't have the contract address, so we need to trace the transaction
    // to get the contract address
    let trace = starknet_provider
        .trace_transaction(transaction_hash)
        .await?;
    let function_invocation = match trace {
        TransactionTrace::Invoke(invoke_trace) => {
            match invoke_trace.execute_invocation {
                ExecuteInvocation::Success(invocation) => Some(invocation),
                ExecuteInvocation::Reverted(_) => {
                    // This should be unreachable as reverted txs only have one event (for sequencer fee transfer)
                    // and so the code must have returned much earlier
                    return Err(TransactionReceiptError::MoreEventsThanExpected);
                }
            }
        }
        TransactionTrace::Declare(_) => None,
        TransactionTrace::DeployAccount(deploy_account_trace) => {
            Some(deploy_account_trace.constructor_invocation)
        }
        TransactionTrace::L1Handler(_) => {
            return Err(TransactionReceiptError::InvalidTransactionType);
        }
    };
    let traced_events = match function_invocation {
        Some(invocation) => get_events_from_function_invocation(invocation, vec![], true),
        None => vec![],
    };

    let mut can_read_events = Vec::new();
    for event in traced_events {
        let has_selector = contract_address_has_selector(
            starknet_provider.clone(),
            event.contract_address,
            BlockId::Tag(BlockTag::Pending),
            CAN_READ_EVENT_SELECTOR,
        )
        .await
        .map_err(SimulationError::StarknetError)?;
        let can_read = if has_selector {
            simulate_boolean_read(
                vec![Call {
                    to: event.contract_address,
                    selector: CAN_READ_EVENT_SELECTOR,
                    calldata: vec![event.event.keys[0]], // first key is the event selector
                }],
                *signed_read_data.read_data().contract_address(),
                starknet_provider.clone(),
            )
            .await
            .map_err(TransactionReceiptError::SimulationError)?
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

    match receipt.receipt {
        TransactionReceipt::Invoke(ref mut invoke_receipt) => {
            invoke_receipt.events = events;
        }
        TransactionReceipt::Declare(ref mut declare_receipt) => {
            declare_receipt.events = events;
        }
        TransactionReceipt::DeployAccount(ref mut deploy_account_receipt) => {
            deploy_account_receipt.events = events;
        }
        _ => {
            return Err(TransactionReceiptError::InvalidTransactionType);
        }
    }

    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use rstest::*;
    use starknet::{accounts::Account, providers::jsonrpc::HttpTransport};

    #[cfg(feature = "testing")]
    use units_primitives::read_data::{
        sign_read_data, ReadData, ReadDataVersion, ReadType, ReadValidity,
    };
    use units_tests_utils::{
        madara::{
            madara_node, madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey,
        },
        scarb::{scarb_build, ArtifactsMap},
    };
    use units_utils::starknet::WaitForReceipt;
    use units_utils::{starknet::StarknetProvider, url::parse_url};

    #[tokio::test]
    async fn test_get_receipt_fails_without_read_signature() {
        // dummy provider as it won't be used
        let provider = Arc::new(StarknetProvider::new(HttpTransport::new(
            parse_url("http://localhost:5050").unwrap(),
        )));
        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider));
        let random_txn_hash = Felt::ONE;

        let receipt = get_transaction_receipt(global_ctx, random_txn_hash, None).await;
        assert_matches!(
            receipt,
            Err(TransactionReceiptError::ReadSignatureNotProvided)
        );
    }

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
        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider.clone()));
        let read_data = ReadData::new(
            account2_with_private_key.account.address(),
            ReadType::TransactionReceipt(result.transaction_hash),
            ReadValidity::Block(1000000),
            provider.chain_id().await.unwrap(),
            ReadDataVersion::ONE,
        );
        let signed_read_data = sign_read_data(read_data, account2_with_private_key.private_key)
            .await
            .unwrap();

        let receipt =
            get_transaction_receipt(global_ctx, result.transaction_hash, Some(signed_read_data))
                .await;
        assert_matches!(receipt, Err(TransactionReceiptError::InvalidSenderAddress));
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
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
        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider.clone()));
        let read_data = ReadData::new(
            account_with_private_key.account.address(),
            ReadType::TransactionReceipt(result.transaction_hash),
            ReadValidity::Block(1000000),
            provider.chain_id().await.unwrap(),
            ReadDataVersion::ONE,
        );
        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let receipt =
            get_transaction_receipt(global_ctx, result.transaction_hash, Some(signed_read_data))
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
        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider.clone()));
        let read_data = ReadData::new(
            account_with_private_key.account.address(),
            ReadType::TransactionReceipt(emit_one_result.transaction_hash),
            ReadValidity::Block(1000000),
            provider.chain_id().await.unwrap(),
            ReadDataVersion::ONE,
        );
        let signed_read_data =
            sign_read_data(read_data.clone(), account_with_private_key.private_key)
                .await
                .unwrap();

        let receipt = get_transaction_receipt(
            global_ctx.clone(),
            emit_one_result.transaction_hash,
            Some(signed_read_data.clone()),
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
            global_ctx.clone(),
            emit_one_result.transaction_hash,
            Some(signed_read_data.clone()),
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

        // Get receipt - should only have TestEventOne since we only have permission for it
        let receipt = get_transaction_receipt(
            global_ctx.clone(),
            emit_one_and_two_result.transaction_hash,
            Some(signed_read_data.clone()),
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
            global_ctx,
            emit_one_and_two_result.transaction_hash,
            Some(signed_read_data),
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
        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider.clone()));
        let read_data = ReadData::new(
            account_with_private_key.account.address(),
            ReadType::TransactionReceipt(result.transaction_hash),
            ReadValidity::Block(1000000),
            provider.chain_id().await.unwrap(),
            ReadDataVersion::ONE,
        );
        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let receipt =
            get_transaction_receipt(global_ctx, result.transaction_hash, Some(signed_read_data))
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
        use starknet::core::types::ExecutionResult;

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
        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider.clone()));
        let read_data = ReadData::new(
            account_with_private_key.account.address(),
            ReadType::TransactionReceipt(declare_result.transaction_hash),
            ReadValidity::Block(1000000),
            provider.chain_id().await.unwrap(),
            ReadDataVersion::ONE,
        );
        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let receipt = get_transaction_receipt(
            global_ctx,
            declare_result.transaction_hash,
            Some(signed_read_data),
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
        use units_tests_utils::starknet::PREDEPLOYED_ACCOUNT_CLASS_HASH;
        use units_utils::starknet::deploy_account;

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
        let global_ctx = Arc::new(GlobalContext::new_with_provider(provider.clone()));
        let read_data = ReadData::new(
            deploy_account_result.contract_address,
            ReadType::TransactionReceipt(deploy_account_result.transaction_hash),
            ReadValidity::Block(1000000),
            provider.chain_id().await.unwrap(),
            ReadDataVersion::ONE,
        );
        let signed_read_data = sign_read_data(read_data, private_key).await.unwrap();

        let receipt = get_transaction_receipt(
            global_ctx,
            deploy_account_result.transaction_hash,
            Some(signed_read_data),
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
}
