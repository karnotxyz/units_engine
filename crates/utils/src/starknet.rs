use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use starknet::{
    accounts::{
        Account, AccountFactory, ExecutionEncoding, OpenZeppelinAccountFactory, SingleOwnerAccount,
    },
    contract::ContractFactory,
    core::types::{
        BlockId, BlockTag, BroadcastedInvokeTransactionV3, Call, ContractClass,
        DataAvailabilityMode, DeclareTransactionResult, DeployAccountTransactionResult,
        ExecuteInvocation, Felt, FlattenedSierraClass, InvokeTransactionResult, ResourceBounds,
        ResourceBoundsMapping, SimulatedTransaction, TransactionReceiptWithBlockInfo,
        TransactionTrace,
    },
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError},
    signers::{LocalWallet, SigningKey},
};

pub type StarknetProvider = JsonRpcClient<HttpTransport>;
pub type StarknetWallet = SingleOwnerAccount<Arc<StarknetProvider>, Arc<LocalWallet>>;

pub async fn get_contract_class(
    starknet_provider: Arc<StarknetProvider>,
    contract_address: Felt,
    block_id: BlockId,
) -> Result<ContractClass, ProviderError> {
    starknet_provider
        .get_class_at(block_id, contract_address)
        .await
}

pub async fn contract_class_has_selector(contract_class: ContractClass, selector: Felt) -> bool {
    match contract_class {
        ContractClass::Sierra(sierra_class) => sierra_class
            .entry_points_by_type
            .external
            .iter()
            .any(|entry_point| entry_point.selector == selector),
        ContractClass::Legacy(legacy_class) => legacy_class
            .entry_points_by_type
            .external
            .iter()
            .any(|entry_point| entry_point.selector == selector),
    }
}

pub async fn contract_address_has_selector(
    starknet_provider: Arc<StarknetProvider>,
    contract_address: Felt,
    block_id: BlockId,
    selector: Felt,
) -> Result<bool, ProviderError> {
    let contract_class = get_contract_class(starknet_provider, contract_address, block_id).await?;
    Ok(contract_class_has_selector(contract_class, selector).await)
}

pub trait GetExecutionResult {
    fn get_execution_result(&self) -> anyhow::Result<ExecuteInvocation>;
}

impl GetExecutionResult for SimulatedTransaction {
    fn get_execution_result(&self) -> anyhow::Result<ExecuteInvocation> {
        match &self.transaction_trace {
            TransactionTrace::Invoke(invoke_transaction) => {
                Ok(invoke_transaction.execute_invocation.clone())
            }
            TransactionTrace::Declare(_) => {
                anyhow::bail!("Declare transactions don't have execution results")
            }
            TransactionTrace::DeployAccount(_) => {
                anyhow::bail!("Deploy account transactions don't have execution results")
            }
            TransactionTrace::L1Handler(l1_handler_transaction) => {
                // L1 Handler transactions won't exist on the chain if they failed
                Ok(ExecuteInvocation::Success(
                    l1_handler_transaction.function_invocation.clone(),
                ))
            }
        }
    }
}

pub async fn wait_for_receipt(
    provider: Arc<StarknetProvider>,
    txn_hash: Felt,
    timeout: Option<Duration>,
) -> anyhow::Result<TransactionReceiptWithBlockInfo> {
    let start_time = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(10));
    let retry_delay = Duration::from_millis(200);

    loop {
        match provider.get_transaction_receipt(txn_hash).await {
            Ok(receipt) => return Ok(receipt),
            Err(err) => match err {
                ProviderError::StarknetError(
                    starknet::core::types::StarknetError::TransactionHashNotFound,
                ) => {
                    if start_time.elapsed() >= timeout {
                        anyhow::bail!("Transaction not found after {:?} timeout", timeout);
                    }
                    tokio::time::sleep(retry_delay).await;
                    continue;
                }
                err => return Err(err.into()),
            },
        }
    }
}

pub async fn deploy_account(
    provider: Arc<StarknetProvider>,
    private_key: Felt,
    class_hash: Felt,
) -> anyhow::Result<DeployAccountTransactionResult> {
    let signer = Arc::new(LocalWallet::from(SigningKey::from_secret_scalar(
        private_key,
    )));
    let chain_id = provider.chain_id().await?;
    let account_factory =
        OpenZeppelinAccountFactory::new(class_hash, chain_id, signer.clone(), provider.clone())
            .await?;

    // Create a deploy account transaction
    Ok(account_factory
        .deploy_v3(Felt::ONE)
        .gas(0)
        .gas_price(0)
        .send()
        .await?)
}

#[allow(async_fn_in_trait)]
pub trait BuildAccount: WaitForReceipt {
    async fn build_account(
        &self,
        provider: Arc<StarknetProvider>,
        private_key: Felt,
    ) -> anyhow::Result<Arc<SingleOwnerAccount<Arc<StarknetProvider>, Arc<LocalWallet>>>>;

    async fn wait_for_receipt_and_build_account(
        &self,
        provider: Arc<StarknetProvider>,
        private_key: Felt,
    ) -> anyhow::Result<Arc<StarknetWallet>> {
        self.wait_for_receipt(provider.clone(), None).await?;
        self.build_account(provider.clone(), private_key).await
    }
}

impl BuildAccount for DeployAccountTransactionResult {
    async fn build_account(
        &self,
        provider: Arc<StarknetProvider>,
        private_key: Felt,
    ) -> anyhow::Result<Arc<StarknetWallet>> {
        let signer = Arc::new(LocalWallet::from(SigningKey::from_secret_scalar(
            private_key,
        )));
        let chain_id = provider.chain_id().await?;

        let mut account = SingleOwnerAccount::new(
            provider,
            signer,
            self.contract_address,
            chain_id,
            ExecutionEncoding::New,
        );
        account.set_block_id(BlockId::Tag(BlockTag::Pending));

        Ok(Arc::new(account))
    }
}

pub async fn declare_contract(
    account: Arc<StarknetWallet>,
    contract_class: Arc<FlattenedSierraClass>,
    compiled_class_hash: Felt,
) -> anyhow::Result<DeclareTransactionResult> {
    Ok(account
        .declare_v3(contract_class, compiled_class_hash)
        .gas(0)
        .gas_price(0)
        .send()
        .await?)
}

pub async fn deploy_contract(
    account: Arc<StarknetWallet>,
    class_hash: Felt,
    constructor_calldata: Vec<Felt>,
    salt: Felt,
    unique: bool,
) -> anyhow::Result<(InvokeTransactionResult, Felt)> {
    let contract_factory = ContractFactory::new(class_hash, account.clone());
    let deployment = contract_factory
        .deploy_v3(constructor_calldata, salt, unique)
        .gas(0)
        .gas_price(0);
    let deployed_address = deployment.deployed_address();
    let invoke_result = deployment.send().await?;

    Ok((invoke_result, deployed_address))
}

#[allow(async_fn_in_trait)]
pub trait WaitForReceipt {
    async fn wait_for_receipt(
        &self,
        provider: Arc<StarknetProvider>,
        timeout: Option<Duration>,
    ) -> anyhow::Result<TransactionReceiptWithBlockInfo>;
}

macro_rules! impl_wait_for_receipt {
    ($t:ty) => {
        impl WaitForReceipt for $t {
            async fn wait_for_receipt(
                &self,
                provider: Arc<StarknetProvider>,
                timeout: Option<Duration>,
            ) -> anyhow::Result<TransactionReceiptWithBlockInfo> {
                wait_for_receipt(provider, self.transaction_hash, timeout).await
            }
        }
    };
}

impl_wait_for_receipt!(DeclareTransactionResult);
impl_wait_for_receipt!(InvokeTransactionResult);
impl_wait_for_receipt!(DeployAccountTransactionResult);

pub async fn build_invoke_simulate_transaction(
    calls: Vec<Call>,
    account_address: Felt,
    provider: Arc<StarknetProvider>,
) -> Result<BroadcastedInvokeTransactionV3, ProviderError> {
    let nonce = provider
        .get_nonce(BlockId::Tag(BlockTag::Pending), account_address)
        .await?;

    Ok(BroadcastedInvokeTransactionV3 {
        sender_address: account_address,
        calldata: encode_calls(&calls, ExecutionEncoding::New),
        signature: vec![],
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
        // Fee market has not been been activated yet so it's hard-coded to be 0
        tip: 0,
        // Hard-coded empty `paymaster_data`
        paymaster_data: vec![],
        // Hard-coded empty `account_deployment_data`
        account_deployment_data: vec![],
        // Hard-coded L1 DA mode for nonce and fee
        nonce_data_availability_mode: DataAvailabilityMode::L1,
        fee_data_availability_mode: DataAvailabilityMode::L1,
        is_query: true,
    })
}

// Taken from https://github.com/xJonathanLEI/starknet-rs/blob/1af6c26d33f404e94e53a81d0fe875dfddfba939/starknet-accounts/src/single_owner.rs#L140
fn encode_calls(calls: &[Call], encoding: ExecutionEncoding) -> Vec<Felt> {
    let mut execute_calldata: Vec<Felt> = vec![calls.len().into()];

    match encoding {
        ExecutionEncoding::Legacy => {
            let mut concated_calldata: Vec<Felt> = vec![];
            for call in calls {
                execute_calldata.push(call.to); // to
                execute_calldata.push(call.selector); // selector
                execute_calldata.push(concated_calldata.len().into()); // data_offset
                execute_calldata.push(call.calldata.len().into()); // data_len

                for item in &call.calldata {
                    concated_calldata.push(*item);
                }
            }

            execute_calldata.push(concated_calldata.len().into()); // calldata_len
            execute_calldata.extend_from_slice(&concated_calldata);
        }
        ExecutionEncoding::New => {
            for call in calls {
                execute_calldata.push(call.to); // to
                execute_calldata.push(call.selector); // selector

                execute_calldata.push(call.calldata.len().into()); // calldata.len()
                execute_calldata.extend_from_slice(&call.calldata);
            }
        }
    }

    execute_calldata
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use starknet::{
        accounts::Account,
        core::types::{
            BlockTag, ExecutionResult, FeeEstimate, InvokeTransactionTrace, PriceUnit,
            RevertedInvocation,
        },
        macros::selector,
    };
    use units_tests_utils::{
        madara::{
            madara_node, madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey,
        },
        starknet::{
            build_declare_trace, build_deploy_account_trace, build_execution_resources,
            build_function_invocation, build_l1_handler_trace, dummy_transfer,
            PREDEPLOYED_ACCOUNT_ADDRESS, PREDEPLOYED_ACCOUNT_CLASS_HASH,
        },
    };

    #[rstest]
    #[tokio::test]
    async fn test_get_contract_class(#[future] madara_node: (MadaraRunner, Arc<StarknetProvider>)) {
        let (_runner, provider) = madara_node.await;

        // Get the contract class of the predeployed account
        match get_contract_class(
            provider.clone(),
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_ADDRESS),
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                panic!("Failed to get contract class: {:?}", e);
            }
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_contract_class_has_selector(
        #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
    ) {
        let (_runner, provider) = madara_node.await;

        // Get the contract class of the predeployed account
        let contract_class = get_contract_class(
            provider.clone(),
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_ADDRESS),
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        .unwrap();

        // Test that __execute__ selector exists
        let execute_selector = selector!("__execute__");
        assert!(contract_class_has_selector(contract_class.clone(), execute_selector).await);

        // Test that a random selector doesn't exist
        let random_selector = Felt::from_hex_unchecked("0xbad");
        assert!(!contract_class_has_selector(contract_class, random_selector).await);
    }

    #[rstest]
    #[tokio::test]
    async fn test_contract_address_has_selector(
        #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
    ) {
        let (_runner, provider) = madara_node.await;

        // Test that __execute__ selector exists
        let execute_selector = selector!("__execute__");
        assert!(contract_address_has_selector(
            provider.clone(),
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_ADDRESS),
            BlockId::Tag(BlockTag::Latest),
            execute_selector
        )
        .await
        .unwrap());

        // Test that a random selector doesn't exist
        let random_selector = Felt::from_hex_unchecked("0xbad");
        assert!(!contract_address_has_selector(
            provider.clone(),
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_ADDRESS),
            BlockId::Tag(BlockTag::Latest),
            random_selector
        )
        .await
        .unwrap());
    }

    #[rstest]
    #[case::success(ExecuteInvocation::Success(build_function_invocation()))]
    #[case::reverted(
        ExecuteInvocation::Reverted(RevertedInvocation {
            revert_reason: "Transaction reverted".into(),
        })
    )]
    fn test_get_execution_result_invoke(#[case] execute_invocation: ExecuteInvocation) {
        let trace = TransactionTrace::Invoke(InvokeTransactionTrace {
            validate_invocation: None,
            execute_invocation: execute_invocation.clone(),
            fee_transfer_invocation: None,
            state_diff: None,
            execution_resources: build_execution_resources(),
        });

        let simulated_transaction = SimulatedTransaction {
            transaction_trace: trace,
            fee_estimation: FeeEstimate {
                gas_consumed: 0.into(),
                gas_price: 0.into(),
                data_gas_consumed: 0.into(),
                data_gas_price: 0.into(),
                overall_fee: 0.into(),
                unit: PriceUnit::Wei,
            },
        };

        let result = simulated_transaction.get_execution_result();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), execute_invocation);
    }

    #[test]
    fn test_get_execution_result_declare() {
        let trace = TransactionTrace::Declare(build_declare_trace());
        let simulated_transaction = SimulatedTransaction {
            transaction_trace: trace,
            fee_estimation: FeeEstimate {
                gas_consumed: 0.into(),
                gas_price: 0.into(),
                data_gas_consumed: 0.into(),
                data_gas_price: 0.into(),
                overall_fee: 0.into(),
                unit: PriceUnit::Wei,
            },
        };

        let result = simulated_transaction.get_execution_result();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Declare transactions don't have execution results"
        );
    }

    #[test]
    fn test_get_execution_result_deploy_account() {
        let trace = TransactionTrace::DeployAccount(build_deploy_account_trace());
        let simulated_transaction = SimulatedTransaction {
            transaction_trace: trace,
            fee_estimation: FeeEstimate {
                gas_consumed: 0.into(),
                gas_price: 0.into(),
                data_gas_consumed: 0.into(),
                data_gas_price: 0.into(),
                overall_fee: 0.into(),
                unit: PriceUnit::Wei,
            },
        };

        let result = simulated_transaction.get_execution_result();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Deploy account transactions don't have execution results"
        );
    }

    #[test]
    fn test_get_execution_result_l1_handler() {
        let l1_handler_trace = build_l1_handler_trace();
        let function_invocation = l1_handler_trace.function_invocation.clone();
        let trace = TransactionTrace::L1Handler(l1_handler_trace);
        let simulated_transaction = SimulatedTransaction {
            transaction_trace: trace,
            fee_estimation: FeeEstimate {
                gas_consumed: 0.into(),
                gas_price: 0.into(),
                data_gas_consumed: 0.into(),
                data_gas_price: 0.into(),
                overall_fee: 0.into(),
                unit: PriceUnit::Wei,
            },
        };

        let result = simulated_transaction.get_execution_result();
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            ExecuteInvocation::Success(function_invocation)
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_wait_for_receipt_success(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let account = accounts_with_private_key[0].account.clone();

        // Do a simple transfer
        let (execution, _) = dummy_transfer(account.clone()).await.unwrap();

        // Wait for receipt
        let receipt = wait_for_receipt(provider, execution.transaction_hash, None)
            .await
            .expect("Failed to get receipt");

        assert_eq!(
            receipt.receipt.execution_result(),
            &ExecutionResult::Succeeded
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_wait_for_receipt_timeout(
        #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
    ) {
        let (_runner, provider) = madara_node.await;

        // Try to get receipt for a non-existent transaction hash
        let fake_hash = Felt::from_hex_unchecked("0x1234");
        let timeout = Duration::from_secs(2);

        let start = Instant::now();
        let result = wait_for_receipt(provider, fake_hash, Some(timeout)).await;

        assert!(result.is_err());
        assert!(start.elapsed() >= timeout);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Transaction not found after 2s timeout"));
    }

    #[rstest]
    #[tokio::test]
    async fn test_deploy_account_success(
        #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
    ) {
        let (_runner, provider) = madara_node.await;

        // Use a test private key and class hash
        let private_key = Felt::from_hex_unchecked("0x1234");
        let class_hash = Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_CLASS_HASH);

        // Deploy the account
        let account = deploy_account(provider.clone(), private_key, class_hash)
            .await
            .expect("Failed to deploy account")
            .wait_for_receipt_and_build_account(provider.clone(), private_key)
            .await
            .expect("Failed to build account");

        // Verify the deployment by checking the class hash at the deployed address
        let deployed_class_hash = provider
            .get_class_hash_at(BlockId::Tag(BlockTag::Pending), account.address())
            .await
            .expect("Failed to get class hash");

        assert_eq!(deployed_class_hash, class_hash);
    }
}
