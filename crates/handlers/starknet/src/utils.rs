use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use starknet::{
    accounts::{
        Account, AccountFactory, ExecutionEncoding, OpenZeppelinAccountFactory, SingleOwnerAccount,
    },
    contract::ContractFactory,
    core::{
        crypto::compute_hash_on_elements,
        types::{
            BlockId, BlockTag, BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV3,
            BroadcastedTransaction, Call, ContractClass, DataAvailabilityMode, DeclareTransaction,
            DeclareTransactionResult, DeployAccountTransaction, DeployAccountTransactionResult,
            ExecuteInvocation, Felt, FlattenedSierraClass, FunctionInvocation, InvokeTransaction,
            InvokeTransactionResult, NonZeroFelt, OrderedEvent, ResourceBounds,
            ResourceBoundsMapping, SimulatedTransaction, SimulationFlag, Transaction,
            TransactionReceiptWithBlockInfo, TransactionTrace,
        },
    },
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError},
    signers::{LocalWallet, SigningKey},
};
use units_primitives::{
    context::ChainHandlerError,
    rpc::{HexBytes32, HexBytes32Error, SendTransactionResult},
};

use crate::{StarknetProvider, StarknetWallet};

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

#[derive(Debug, thiserror::Error)]
pub enum WaitForReceiptError {
    #[error("Transaction not found after {0} timeout")]
    TransactionNotFound(u64),
    #[error("Starknet error: {0}")]
    StarknetError(#[from] ProviderError),
    #[error("Failed to convert transaction hash to Felt: {0}")]
    TransactionHashConversionError(#[from] HexBytes32Error),
}

impl From<WaitForReceiptError> for ChainHandlerError {
    fn from(value: WaitForReceiptError) -> Self {
        match value {
            WaitForReceiptError::TransactionNotFound(_) => {
                ChainHandlerError::TransactionNotFound(value.to_string())
            }
            WaitForReceiptError::StarknetError(err) => {
                ChainHandlerError::ProviderError(err.to_string())
            }
            WaitForReceiptError::TransactionHashConversionError(err) => {
                ChainHandlerError::ConversionError(err.to_string())
            }
        }
    }
}

pub async fn wait_for_receipt(
    provider: Arc<StarknetProvider>,
    txn_hash: Felt,
    timeout: Option<Duration>,
) -> Result<TransactionReceiptWithBlockInfo, WaitForReceiptError> {
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
                        return Err(WaitForReceiptError::TransactionNotFound(timeout.as_secs()));
                    }
                    tokio::time::sleep(retry_delay).await;
                    continue;
                }
                err => return Err(WaitForReceiptError::StarknetError(err)),
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
    ) -> Result<TransactionReceiptWithBlockInfo, WaitForReceiptError>;
}

macro_rules! impl_wait_for_receipt {
    ($t:ty) => {
        impl WaitForReceipt for $t {
            async fn wait_for_receipt(
                &self,
                provider: Arc<StarknetProvider>,
                timeout: Option<Duration>,
            ) -> Result<TransactionReceiptWithBlockInfo, WaitForReceiptError> {
                wait_for_receipt(provider, self.transaction_hash, timeout).await
            }
        }
    };
}

impl_wait_for_receipt!(DeclareTransactionResult);
impl_wait_for_receipt!(InvokeTransactionResult);
impl_wait_for_receipt!(DeployAccountTransactionResult);

impl WaitForReceipt for SendTransactionResult {
    async fn wait_for_receipt(
        &self,
        provider: Arc<StarknetProvider>,
        timeout: Option<Duration>,
    ) -> Result<TransactionReceiptWithBlockInfo, WaitForReceiptError> {
        wait_for_receipt(
            provider,
            self.transaction_hash
                .try_into()
                .map_err(WaitForReceiptError::TransactionHashConversionError)?,
            timeout,
        )
        .await
    }
}
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

#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    #[error("Failed to read execution result")]
    FailedExecutionResultRead(anyhow::Error),
    #[error("Empty boolean read result")]
    EmptyBooleanReadResult,
    #[error("Starknet error: {0}")]
    StarknetError(#[from] ProviderError),
}

pub async fn simulate_boolean_read(
    calls: Vec<Call>,
    account_address: Felt,
    provider: Arc<StarknetProvider>,
) -> Result<bool, SimulationError> {
    let simulation =
        build_invoke_simulate_transaction(calls, account_address, provider.clone()).await?;

    let simulated_txn = provider
        .simulate_transaction(
            BlockId::Tag(BlockTag::Pending),
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V3(simulation)),
            vec![SimulationFlag::SkipFeeCharge, SimulationFlag::SkipValidate],
        )
        .await?;

    match simulated_txn
        .get_execution_result()
        .map_err(SimulationError::FailedExecutionResultRead)?
    {
        ExecuteInvocation::Success(function_invocation) => {
            let can_read = function_invocation
                .result
                .get(2)
                .ok_or(SimulationError::EmptyBooleanReadResult)?;
            if can_read != &Felt::ONE {
                return Ok(false);
            }
            Ok(true)
        }
        ExecuteInvocation::Reverted(_) => Ok(false),
    }
}

// Taken from https://github.com/xJonathanLEI/starknet-rs/blob/1af6c26d33f404e94e53a81d0fe875dfddfba939/starknet-accounts/src/single_owner.rs#L140
pub fn encode_calls(calls: &[Call], encoding: ExecutionEncoding) -> Vec<Felt> {
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

#[derive(Debug, Clone)]
pub struct OrderedEventWithContractAddress {
    pub contract_address: Felt,
    pub event: OrderedEvent,
}

pub fn get_events_from_function_invocation(
    invocation: FunctionInvocation,
    mut events: Vec<OrderedEventWithContractAddress>,
    sorted: bool,
) -> Vec<OrderedEventWithContractAddress> {
    for call in invocation.calls {
        events = get_events_from_function_invocation(call, events, false);
    }
    events.extend(
        invocation
            .events
            .into_iter()
            .map(|event| OrderedEventWithContractAddress {
                contract_address: invocation.contract_address,
                event,
            }),
    );
    if sorted {
        events.sort_by_key(|event| event.event.order);
    }
    events
}

// Taken from https://github.com/apoorvsadana/starknet-rs/blob/4a2eacc2f8139d9a8138e549c85df1a8b546098a/starknet-accounts/src/factory/mod.rs#L1088
pub fn calculate_contract_address(
    salt: Felt,
    class_hash: Felt,
    constructor_calldata: &[Felt],
) -> Felt {
    /// Cairo string for `STARKNET_CONTRACT_ADDRESS`
    const PREFIX_CONTRACT_ADDRESS: Felt = Felt::from_raw([
        533439743893157637,
        8635008616843941496,
        17289941567720117366,
        3829237882463328880,
    ]);
    // 2 ** 251 - 256
    const ADDR_BOUND: NonZeroFelt = NonZeroFelt::from_raw([
        576459263475590224,
        18446744073709255680,
        160989183,
        18446743986131443745,
    ]);

    compute_hash_on_elements(&[
        PREFIX_CONTRACT_ADDRESS,
        Felt::ZERO,
        salt,
        class_hash,
        compute_hash_on_elements(constructor_calldata),
    ])
    .mod_floor(&ADDR_BOUND)
}

pub trait GetSenderAddress {
    fn get_sender_address(&self) -> Option<Felt>;
}

impl GetSenderAddress for Transaction {
    fn get_sender_address(&self) -> Option<Felt> {
        match self {
            Transaction::Invoke(invoke_txn) => match invoke_txn {
                InvokeTransaction::V0(invoke_txn_v0) => Some(invoke_txn_v0.contract_address),
                InvokeTransaction::V1(invoke_txn_v1) => Some(invoke_txn_v1.sender_address),
                InvokeTransaction::V3(invoke_txn_v3) => Some(invoke_txn_v3.sender_address),
            },
            Transaction::Declare(declare_txn) => match declare_txn {
                DeclareTransaction::V0(declare_txn_v0) => Some(declare_txn_v0.sender_address),
                DeclareTransaction::V1(declare_txn_v1) => Some(declare_txn_v1.sender_address),
                DeclareTransaction::V2(declare_txn_v2) => Some(declare_txn_v2.sender_address),
                DeclareTransaction::V3(declare_txn_v3) => Some(declare_txn_v3.sender_address),
            },
            Transaction::DeployAccount(deploy_account_txn) => match deploy_account_txn {
                DeployAccountTransaction::V1(deploy_account_txn_v1) => {
                    Some(calculate_contract_address(
                        deploy_account_txn_v1.contract_address_salt,
                        deploy_account_txn_v1.class_hash,
                        &deploy_account_txn_v1.constructor_calldata,
                    ))
                }
                DeployAccountTransaction::V3(deploy_account_txn_v3) => {
                    Some(calculate_contract_address(
                        deploy_account_txn_v3.contract_address_salt,
                        deploy_account_txn_v3.class_hash,
                        &deploy_account_txn_v3.constructor_calldata,
                    ))
                }
            },
            // Deploy transactions are deprecated
            Transaction::Deploy(_) => None,
            // L1 handler transactions don't have a sender address (maybe we can handle showing L1 from address later)
            Transaction::L1Handler(_) => None,
        }
    }
}

pub trait ToFelt<T, E> {
    fn to_felt(self) -> Result<T, E>;
}

impl ToFelt<Felt, ChainHandlerError> for HexBytes32 {
    fn to_felt(self) -> Result<Felt, ChainHandlerError> {
        self.try_into()
            .map_err(|e: HexBytes32Error| ChainHandlerError::BadRequest(e.to_string()))
    }
}

impl ToFelt<Vec<Felt>, ChainHandlerError> for Vec<HexBytes32> {
    fn to_felt(self) -> Result<Vec<Felt>, ChainHandlerError> {
        let mut result = Vec::with_capacity(self.len());
        for hex_bytes32 in self {
            result.push(hex_bytes32.to_felt()?);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::utils::{
        madara::{
            madara_node, madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey,
        },
        starknet::{
            build_declare_trace, build_deploy_account_trace, build_execution_resources,
            build_function_invocation, build_l1_handler_trace, dummy_transfer,
            PREDEPLOYED_ACCOUNT_ADDRESS, PREDEPLOYED_ACCOUNT_CLASS_HASH,
        },
    };
    use assert_matches::assert_matches;
    use rstest::*;
    use starknet::{
        accounts::Account,
        core::types::{
            BlockTag, ExecutionResult, FeeEstimate, InvokeTransactionTrace, PriceUnit,
            RevertedInvocation,
        },
        macros::selector,
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
        assert_matches!(
            result.unwrap_err(),
            WaitForReceiptError::TransactionNotFound(_)
        );
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
