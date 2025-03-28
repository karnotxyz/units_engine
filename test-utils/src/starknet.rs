use starknet::{
    accounts::{
        Account, AccountFactory, ConnectedAccount, ExecutionEncoding, OpenZeppelinAccountFactory,
        SingleOwnerAccount,
    },
    core::types::{
        BlockId, BlockTag, Call, CallType, ComputationResources, DataAvailabilityResources,
        DataResources, DeclareTransactionTrace, DeployAccountTransactionTrace, EntryPointType,
        ExecuteInvocation, ExecutionResources, ExecutionResult, Felt, FunctionInvocation,
        InvokeTransactionResult, InvokeTransactionTrace, L1HandlerTransactionTrace,
        TransactionReceiptWithBlockInfo,
    },
    macros::selector,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError},
    signers::{LocalWallet, SigningKey},
};
use std::sync::Arc;
use tokio::time::{sleep, Duration, Instant};
use units_utils::starknet::StarknetProvider;

pub const PREDEPLOYED_ACCOUNT_CLASS_HASH: &str =
    "0x00e2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6";
pub const ETH_TOKEN_ADDRESS: &str =
    "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
pub const PREDEPLOYED_ACCOUNT_ADDRESS: &str =
    "0x055be462e718c4166d656d11f89e341115b8bc82389c3762a10eade04fcb225d";

pub async fn wait_for_receipt(
    provider: Arc<StarknetProvider>,
    txn_hash: Felt,
) -> anyhow::Result<TransactionReceiptWithBlockInfo> {
    let start_time = Instant::now();
    let timeout = Duration::from_secs(10);
    let retry_delay = Duration::from_millis(200);

    loop {
        match provider.get_transaction_receipt(txn_hash).await {
            Ok(receipt) => return Ok(receipt),
            Err(err) => match err {
                ProviderError::StarknetError(
                    starknet::core::types::StarknetError::TransactionHashNotFound,
                ) => {
                    if start_time.elapsed() >= timeout {
                        anyhow::bail!("Transaction not found after 10 seconds timeout");
                    }
                    sleep(retry_delay).await;
                    continue;
                }
                err => return Err(err.into()),
            },
        }
    }
}

pub async fn deploy_dummy_account(
    provider: Arc<StarknetProvider>,
) -> anyhow::Result<Arc<SingleOwnerAccount<Arc<StarknetProvider>, Arc<LocalWallet>>>> {
    let signer = Arc::new(LocalWallet::from(SigningKey::from_secret_scalar(Felt::ONE)));
    let chain_id = provider.chain_id().await.unwrap();
    let account_factory = OpenZeppelinAccountFactory::new(
        Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_CLASS_HASH),
        chain_id,
        signer.clone(),
        provider.clone(),
    )
    .await
    .unwrap();

    // Create a deploy account transaction
    let deployment = account_factory
        .deploy_v3(Felt::ONE)
        .gas(0)
        .gas_price(0)
        .send()
        .await
        .unwrap();

    let receipt = wait_for_receipt(provider.clone(), deployment.transaction_hash).await?;

    let mut account = SingleOwnerAccount::new(
        provider,
        signer,
        deployment.contract_address,
        chain_id,
        ExecutionEncoding::New,
    );

    assert_eq!(
        *receipt.receipt.execution_result(),
        ExecutionResult::Succeeded
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    Ok(Arc::new(account))
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
    let receipt = wait_for_receipt(wallet.provider().clone(), txn.transaction_hash).await?;
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
