use crate::utils::wait_for_receipt;
use crate::{StarknetContext, StarknetProvider, StarknetWallet};
use anyhow::Context;
use starknet::providers::Provider;
use starknet::{
    accounts::{Account, ConnectedAccount, ExecutionEncoding, SingleOwnerAccount},
    core::types::{
        Call, CallType, ContractClass, DeclareTransactionTrace, DeployAccountTransactionTrace,
        EntryPointType, ExecuteInvocation, ExecutionResources, Felt, FlattenedSierraClass,
        FunctionInvocation, InnerCallExecutionResources, InvokeTransactionResult,
        InvokeTransactionTrace, L1HandlerTransactionTrace, TransactionReceiptWithBlockInfo,
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
pub const STRK_TOKEN_ADDRESS: &str =
    "0x04718f5a0Fc34cC1AF16A1cdee98fFB20C31f5cD61D6Ab07201858f4287c938D";
pub const PREDEPLOYED_ACCOUNT_ADDRESS: &str =
    "0x055be462e718c4166d656d11f89e341115b8bc82389c3762a10eade04fcb225d";
pub const PREDEPLOYED_ACCOUNT_PRIVATE_KEY: &str =
    "0x077e56c6dc32d40a67f6f7e6625c8dc5e570abe49c0a24e9202e4ae906abcc07";

pub async fn dummy_transfer(
    wallet: Arc<SingleOwnerAccount<Arc<StarknetProvider>, Arc<LocalWallet>>>,
    recipient: Felt,
    amount: Felt,
) -> anyhow::Result<(InvokeTransactionResult, TransactionReceiptWithBlockInfo)> {
    let txn = wallet
        .execute_v3(vec![Call {
            to: Felt::from_hex_unchecked(STRK_TOKEN_ADDRESS),
            selector: selector!("transfer"),
            calldata: vec![
                recipient,                       // recipient
                amount,                          // amount_low
                Felt::from_hex_unchecked("0x0"), // amount_high
            ],
        }])
        .send()
        .await
        .context("Failed to transfer")?;
    let receipt = wait_for_receipt(wallet.provider().clone(), txn.transaction_hash, None).await?;
    Ok((txn, receipt))
}

pub async fn fund_account_devnet(
    provider: Arc<StarknetProvider>,
    account_address: Felt,
) -> anyhow::Result<()> {
    // Funding account using predeployed devnet account
    let signer =
        SigningKey::from_secret_scalar(Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_PRIVATE_KEY));
    let local_wallet = Arc::new(LocalWallet::from(signer));
    let predeployed_account_devnet = SingleOwnerAccount::new(
        provider.clone(),
        local_wallet,
        Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_ADDRESS),
        provider.chain_id().await?,
        ExecutionEncoding::New,
    );
    dummy_transfer(
        Arc::new(predeployed_account_devnet),
        account_address,
        Felt::from(Felt::from_dec_str("1000000000000000000").unwrap()), // 10^18
    )
    .await
    .context("Failed to fund account")?;
    Ok(())
}

pub fn build_execution_resources() -> ExecutionResources {
    ExecutionResources {
        l1_gas: 0,
        l1_data_gas: 0,
        l2_gas: 0,
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
        execution_resources: InnerCallExecutionResources {
            l1_gas: 0,
            l2_gas: 0,
        },
        is_reverted: false,
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
        function_invocation: ExecuteInvocation::Success(build_function_invocation()),
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

#[async_trait::async_trait]
pub trait ProviderToDummyGlobalContext {
    async fn provider_to_dummy_global_context(&self) -> Arc<GlobalContext>;
}

#[async_trait::async_trait]
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
