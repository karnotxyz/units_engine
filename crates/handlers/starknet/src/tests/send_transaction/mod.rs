use rstest::*;
use starknet::{
    accounts::{Account, ExecutionEncoding},
    core::types::{BlockId, BlockTag},
};

use crate::utils::WaitForReceipt;
use crate::StarknetProvider;
use crate::{
    tests::utils::{
        madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
        scarb::{scarb_build, ArtifactsMap},
    },
    utils::encode_calls,
};
use starknet::core::types::ExecutionResult;
use starknet::macros::selector;
use std::sync::Arc;
use units_primitives::rpc::SendTransactionParams;

use starknet::core::types::Call;
use starknet::core::types::Felt;
use starknet::providers::Provider;
use units_handlers_common::send_transaction::send_transaction;

use crate::tests::utils::starknet::ProviderToDummyGlobalContext;

#[cfg(feature = "testing")]
#[rstest]
#[tokio::test]
async fn test_add_invoke_transaction(
    #[future] madara_node_with_accounts: (
        MadaraRunner,
        Arc<StarknetProvider>,
        Vec<StarknetWalletWithPrivateKey>,
    ),
    #[future]
    #[with("src/tests/send_transaction/test_contracts")]
    scarb_build: ArtifactsMap,
) {
    let (_runner, provider, accounts) = madara_node_with_accounts.await;
    let global_ctx = provider.provider_to_dummy_global_context().await;

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
            BlockId::Tag(BlockTag::PreConfirmed),
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
        .nonce(nonce)
        .prepared()
        .unwrap()
        .transaction_hash(false);
    let signature = accounts[0].sign_message(&txn_hash);
    // Invoke the contract
    let invoke_tx_result = send_transaction(
        global_ctx,
        SendTransactionParams {
            account_address: accounts[0].account.address().into(),
            signature: vec![signature.r.into(), signature.s.into()],
            nonce: nonce.try_into().unwrap(),
            calldata: encode_calls(&calls, ExecutionEncoding::New)
                .into_iter()
                .map(|x| x.into())
                .collect(),
        },
    )
    .await
    .unwrap();

    let receipt = invoke_tx_result
        .wait_for_receipt(provider, None)
        .await
        .unwrap();
    assert_eq!(
        receipt.receipt.execution_result(),
        &ExecutionResult::Succeeded
    );
}
