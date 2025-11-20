use assert_matches::assert_matches;
use rstest::*;
use starknet::accounts::Account;
use units_handlers_common::call::call;
#[cfg(feature = "testing")]
use units_primitives::read_data::sign_read_data;
use units_primitives::read_data::{
    ReadData, ReadDataVersion, ReadType, ReadValidity, ReadVerifier, VerifierAccount,
};
use units_primitives::rpc::CallParams;

use crate::StarknetProvider;
use crate::{
    tests::utils::{
        madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
        scarb::{scarb_build, ArtifactsMap},
    },
    utils::WaitForReceipt,
};
use starknet::core::types::Felt;
use starknet::macros::selector;
use starknet::providers::Provider;
use std::sync::Arc;

use super::utils::starknet::ProviderToDummyGlobalContext;

#[rstest]
#[tokio::test]
#[cfg(feature = "testing")]
async fn test_counter_increment(
    #[future]
    #[with("src/tests/call/test_contracts")]
    scarb_build: ArtifactsMap,
    #[future] madara_node_with_accounts: (
        MadaraRunner,
        Arc<StarknetProvider>,
        Vec<StarknetWalletWithPrivateKey>,
    ),
) {
    use units_handlers_common::call::CallError;

    let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
    let account = accounts_with_private_key[0].account.clone();

    let mut artifacts = scarb_build.await;
    let counter_artifact = artifacts.remove("CounterContract").unwrap();
    let counter_address = counter_artifact
        .declare_and_deploy_and_wait_for_receipt(account.clone(), vec![], Felt::ZERO, false)
        .await;

    // Call increment
    let result = account
        .execute_v3(vec![starknet::core::types::Call {
            to: counter_address,
            selector: selector!("increment"),
            calldata: vec![],
        }])
        .send()
        .await
        .unwrap();

    // Wait for the transaction to be executed
    result
        .wait_for_receipt(provider.clone(), None)
        .await
        .unwrap();

    // Verify counter value
    let global_ctx = provider.provider_to_dummy_global_context().await;
    let read_data = ReadData::new(
        ReadVerifier::Account(VerifierAccount {
            signer_address: account.address(),
        }),
        vec![ReadType::Call {
            contract_address: counter_address,
            function_selector: selector!("get_counter"),
            calldata: vec![],
        }],
        ReadValidity::Block { block: 1000000 },
        provider.chain_id().await.unwrap(),
        ReadDataVersion::One,
    );
    let signed_read_data =
        sign_read_data(read_data.clone(), accounts_with_private_key[0].private_key)
            .await
            .unwrap();
    let counter_value = call(
        global_ctx.clone(),
        CallParams {
            contract_address: counter_address.into(),
            function_name: "get_counter".to_string(),
            calldata: vec![],
            signed_read_data: signed_read_data.clone(),
        },
    )
    .await
    .unwrap();

    assert_eq!(counter_value.result[0], Felt::from(1).into());

    // Then decrement
    let result = account
        .execute_v3(vec![starknet::core::types::Call {
            to: counter_address,
            selector: selector!("decrement"),
            calldata: vec![],
        }])
        .send()
        .await
        .unwrap();

    result
        .wait_for_receipt(provider.clone(), None)
        .await
        .unwrap();

    let counter_value = call(
        global_ctx.clone(),
        CallParams {
            contract_address: counter_address.into(),
            function_name: "get_counter".to_string(),
            calldata: vec![],
            signed_read_data,
        },
    )
    .await
    .unwrap();

    assert_eq!(counter_value.result[2], Felt::from(0).into());

    // Read with invalid signature
    let signed_read_data = sign_read_data(read_data, Felt::THREE).await.unwrap();
    let counter_value = call(
        global_ctx,
        CallParams {
            contract_address: counter_address.into(),
            function_name: "get_counter".to_string(),
            calldata: vec![],
            signed_read_data,
        },
    )
    .await;

    assert_matches!(counter_value, Err(CallError::InvalidReadSignature));
}

#[rstest]
#[tokio::test]
#[cfg(feature = "testing")]
async fn test_read_with_approval(
    #[future]
    #[with("src/tests/call/test_contracts")]
    scarb_build: ArtifactsMap,
    #[future]
    #[with(2)]
    madara_node_with_accounts: (
        MadaraRunner,
        Arc<StarknetProvider>,
        Vec<StarknetWalletWithPrivateKey>,
    ),
) {
    use units_handlers_common::call::CallError;
    use units_primitives::context::ChainHandlerError;

    let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
    let owner_account = accounts_with_private_key[0].account.clone();
    let user_account = accounts_with_private_key[1].account.clone();

    let mut artifacts = scarb_build.await;
    let read_with_approval_artifact = artifacts.remove("ReadWithApproval").unwrap();
    let contract_address = read_with_approval_artifact
        .declare_and_deploy_and_wait_for_receipt(
            owner_account.clone(),
            vec![Felt::from(42)],
            Felt::ZERO,
            false,
        )
        .await;

    // Owner tries to read (should work)
    let global_ctx = provider.provider_to_dummy_global_context().await;
    let read_data = ReadData::new(
        ReadVerifier::Account(VerifierAccount {
            signer_address: owner_account.address(),
        }),
        vec![ReadType::Call {
            contract_address,
            function_selector: selector!("read_value"),
            calldata: vec![],
        }],
        ReadValidity::Block { block: 1000000 },
        provider.chain_id().await.unwrap(),
        ReadDataVersion::One,
    );
    let signed_read_data =
        sign_read_data(read_data.clone(), accounts_with_private_key[0].private_key)
            .await
            .unwrap();

    let value = call(
        global_ctx.clone(),
        CallParams {
            contract_address: contract_address.into(),
            function_name: "read_value".to_string(),
            calldata: vec![],
            signed_read_data: signed_read_data.clone(),
        },
    )
    .await
    .unwrap();

    assert_eq!(value.result[2], Felt::from(42).into());

    // User tries to read (should fail)
    let user_read_data = ReadData::new(
        ReadVerifier::Account(VerifierAccount {
            signer_address: user_account.address(),
        }),
        vec![ReadType::Call {
            contract_address,
            function_selector: selector!("read_value"),
            calldata: vec![],
        }],
        ReadValidity::Block { block: 1000000 },
        provider.chain_id().await.unwrap(),
        ReadDataVersion::One,
    );
    let user_signed_read_data = sign_read_data(
        user_read_data.clone(),
        accounts_with_private_key[1].private_key,
    )
    .await
    .unwrap();

    let user_value = call(
        global_ctx.clone(),
        CallParams {
            contract_address: contract_address.into(),
            function_name: "read_value".to_string(),
            calldata: vec![],
            signed_read_data: user_signed_read_data.clone(),
        },
    )
    .await;

    assert_matches!(
        user_value,
        Err(CallError::ChainHandlerError(
            ChainHandlerError::SimulationReverted(_)
        ))
    );

    // Owner approves user
    let result = owner_account
        .execute_v3(vec![starknet::core::types::Call {
            to: contract_address,
            selector: selector!("add_approved_user"),
            calldata: vec![user_account.address()],
        }])
        .send()
        .await
        .unwrap();

    result
        .wait_for_receipt(provider.clone(), None)
        .await
        .unwrap();

    // User tries to read again (should work now)
    let user_value = call(
        global_ctx,
        CallParams {
            contract_address: contract_address.into(),
            function_name: "read_value".to_string(),
            calldata: vec![],
            signed_read_data: user_signed_read_data,
        },
    )
    .await
    .unwrap();

    assert_eq!(user_value.result[2], Felt::from(42).into());
}
