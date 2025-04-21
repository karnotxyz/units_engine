use crate::utils::{deploy_account, wait_for_receipt, BuildAccount};
use crate::{StarknetContext, StarknetProvider, StarknetWallet};
use starknet::{
    accounts::{Account, ConnectedAccount, ExecutionEncoding, SingleOwnerAccount},
    core::types::{
        Call, CallType, ComputationResources, ContractClass, DataAvailabilityResources,
        DataResources, DeclareTransactionTrace, DeployAccountTransactionTrace, EntryPointType,
        ExecuteInvocation, ExecutionResources, Felt, FlattenedSierraClass, FunctionInvocation,
        InvokeTransactionResult, InvokeTransactionTrace, L1HandlerTransactionTrace,
        TransactionReceiptWithBlockInfo,
    },
    macros::selector,
    providers::jsonrpc::HttpTransport,
    signers::{LocalWallet, SigningKey},
};
use std::sync::Arc;
use units_primitives::context::{ChainHandler, GlobalContext};
use url::Url;

pub const PREDEPLOYED_ACCOUNT_CLASS_HASH: &str =
    "0x00e2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6";
pub const ETH_TOKEN_ADDRESS: &str =
    "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
pub const PREDEPLOYED_ACCOUNT_ADDRESS: &str =
    "0x055be462e718c4166d656d11f89e341115b8bc82389c3762a10eade04fcb225d";

pub async fn deploy_dummy_account(
    provider: Arc<StarknetProvider>,
) -> anyhow::Result<Arc<StarknetWallet>> {
    let private_key = Felt::ONE;
    deploy_account(
        provider.clone(),
        private_key,
        Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_CLASS_HASH),
    )
    .await
    .expect("Failed to deploy account")
    .wait_for_receipt_and_build_account(provider.clone(), private_key)
    .await
}

pub async fn dummy_transfer(
    wallet: Arc<SingleOwnerAccount<Arc<StarknetProvider>, Arc<LocalWallet>>>,
) -> anyhow::Result<(InvokeTransactionResult, TransactionReceiptWithBlockInfo)> {
    let txn = wallet
        .execute_v3(vec![Call {
            to: Felt::from_hex_unchecked(ETH_TOKEN_ADDRESS),
            selector: selector!("transfer"),
            calldata: vec![
                Felt::from_hex_unchecked("0x1"), // recipient
                Felt::from_hex_unchecked("0x0"), // amount_low
                Felt::from_hex_unchecked("0x0"), // amount_high
            ],
        }])
        .gas(0)
        .gas_price(0)
        .send()
        .await?;
    let receipt = wait_for_receipt(wallet.provider().clone(), txn.transaction_hash, None).await?;
    Ok((txn, receipt))
}

pub fn build_computation_resources() -> ComputationResources {
    ComputationResources {
        steps: 0,
        memory_holes: None,
        range_check_builtin_applications: None,
        pedersen_builtin_applications: None,
        poseidon_builtin_applications: None,
        ec_op_builtin_applications: None,
        ecdsa_builtin_applications: None,
        bitwise_builtin_applications: None,
        keccak_builtin_applications: None,
        segment_arena_builtin: None,
    }
}

pub fn build_data_resources() -> DataResources {
    DataResources {
        data_availability: DataAvailabilityResources {
            l1_gas: 0,
            l1_data_gas: 0,
        },
    }
}

pub fn build_execution_resources() -> ExecutionResources {
    ExecutionResources {
        computation_resources: build_computation_resources(),
        data_resources: build_data_resources(),
    }
}

pub fn build_function_invocation() -> FunctionInvocation {
    FunctionInvocation {
        contract_address: Felt::from(0),
        entry_point_selector: Felt::from(0),
        calldata: vec![],
        caller_address: Felt::from(0),
        class_hash: Felt::from(0),
        entry_point_type: EntryPointType::External,
        call_type: CallType::Call,
        result: vec![],
        calls: vec![],
        events: vec![],
        messages: vec![],
        execution_resources: build_computation_resources(),
    }
}

pub fn build_invoke_trace() -> InvokeTransactionTrace {
    InvokeTransactionTrace {
        validate_invocation: None,
        execute_invocation: ExecuteInvocation::Success(build_function_invocation()),
        fee_transfer_invocation: None,
        state_diff: None,
        execution_resources: build_execution_resources(),
    }
}

pub fn build_declare_trace() -> DeclareTransactionTrace {
    DeclareTransactionTrace {
        validate_invocation: None,
        fee_transfer_invocation: None,
        state_diff: None,
        execution_resources: build_execution_resources(),
    }
}

pub fn build_deploy_account_trace() -> DeployAccountTransactionTrace {
    DeployAccountTransactionTrace {
        validate_invocation: None,
        constructor_invocation: build_function_invocation(),
        fee_transfer_invocation: None,
        state_diff: None,
        execution_resources: build_execution_resources(),
    }
}

pub fn build_l1_handler_trace() -> L1HandlerTransactionTrace {
    L1HandlerTransactionTrace {
        function_invocation: build_function_invocation(),
        state_diff: None,
        execution_resources: build_execution_resources(),
    }
}

pub fn assert_contract_class_eq(expected: FlattenedSierraClass, actual: ContractClass) {
    match actual {
        ContractClass::Sierra(actual) => {
            assert_eq!(expected, actual);
        }
        _ => panic!("Contract class is not a Sierra class"),
    }
}

pub trait TestDefault {
    fn test_default() -> Self;
}

impl TestDefault for StarknetWallet {
    fn test_default() -> Self {
        let provider = Arc::new(StarknetProvider::new(HttpTransport::new(
            Url::parse("http://localhost:5050").unwrap(),
        )));
        let signer = Arc::new(LocalWallet::from(SigningKey::from_secret_scalar(
            Felt::ZERO,
        )));
        SingleOwnerAccount::new(
            provider,
            signer,
            Felt::ZERO,
            Felt::ZERO,
            ExecutionEncoding::New,
        )
    }
}

pub trait ProviderToDummyGlobalContext {
    async fn provider_to_dummy_global_context(&self) -> Arc<GlobalContext>;
}

impl ProviderToDummyGlobalContext for Arc<StarknetProvider> {
    async fn provider_to_dummy_global_context(&self) -> Arc<GlobalContext> {
        let starknet_ctx: Arc<Box<dyn ChainHandler>> = Arc::new(Box::new(
            StarknetContext::new_with_provider(
                self.clone(),
                Felt::ONE.into(),
                Felt::ZERO.into(),
                Felt::ZERO.into(),
            )
            .await
            .unwrap(),
        ));
        Arc::new(GlobalContext::new(starknet_ctx))
    }
}
