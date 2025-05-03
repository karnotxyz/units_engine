use assert_matches::assert_matches;
use rstest::*;
use starknet::accounts::Account;

use crate::tests::utils::{
    madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
    scarb::{scarb_build, ArtifactsMap},
};
use crate::StarknetProvider;
use std::sync::Arc;
#[cfg(feature = "testing")]
use units_primitives::read_data::{
    sign_read_data, ReadData, ReadDataVersion, ReadType, ReadValidity,
};
use units_primitives::{
    read_data::{ReadVerifier, VerifierAccount},
    rpc::{GetNonceParams, GetNonceResult},
};

use starknet::core::types::Felt;
use starknet::providers::Provider;
use units_handlers_common::get_nonce::{get_nonce, GetNonceError};

use crate::tests::utils::starknet::ProviderToDummyGlobalContext;

#[rstest]
#[tokio::test]
async fn test_can_read_nonce_does_not_exist(
    #[future]
    #[with("src/tests/get_nonce/test_contracts")]
    scarb_build: ArtifactsMap,
    #[future] madara_node_with_accounts: (
        MadaraRunner,
        Arc<StarknetProvider>,
        Vec<StarknetWalletWithPrivateKey>,
    ),
) {
    let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
    let account = accounts_with_private_key[0].account.clone();

    let mut artifacts = scarb_build.await;
    let artifact_without_can_read_nonce = artifacts.remove("ContractWithoutCanReadNonce").unwrap();
    let address = artifact_without_can_read_nonce
        .declare_and_deploy_and_wait_for_receipt(account, vec![], Felt::ZERO, false)
        .await;

    let global_ctx = provider.provider_to_dummy_global_context().await;
    let nonce = get_nonce(
        global_ctx,
        GetNonceParams {
            account_address: address.into(),
            signed_read_data: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(nonce, GetNonceResult { nonce: 0 });
}

#[rstest]
#[tokio::test]
async fn test_can_read_nonce_returns_without_read_data(
    #[future]
    #[with("src/tests/get_nonce/test_contracts")]
    scarb_build: ArtifactsMap,
    #[future] madara_node_with_accounts: (
        MadaraRunner,
        Arc<StarknetProvider>,
        Vec<StarknetWalletWithPrivateKey>,
    ),
) {
    let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
    let account = accounts_with_private_key[0].account.clone();

    let mut artifacts = scarb_build.await;
    let artifact_without_can_read_nonce =
        artifacts.remove("ContractWithCanReadNonceFalse").unwrap();
    let address = artifact_without_can_read_nonce
        .declare_and_deploy_and_wait_for_receipt(account, vec![], Felt::ZERO, false)
        .await;

    let global_ctx = provider.provider_to_dummy_global_context().await;
    let nonce = get_nonce(
        global_ctx,
        GetNonceParams {
            account_address: address.into(),
            signed_read_data: None,
        },
    )
    .await;
    assert_matches!(nonce, Err(GetNonceError::ReadSignatureNotProvided));
}

#[rstest]
#[tokio::test]
#[cfg(feature = "testing")]
async fn test_can_read_nonce_returns_invalid_read_signature(
    #[future]
    #[with("src/tests/get_nonce/test_contracts")]
    scarb_build: ArtifactsMap,
    #[future] madara_node_with_accounts: (
        MadaraRunner,
        Arc<StarknetProvider>,
        Vec<StarknetWalletWithPrivateKey>,
    ),
) {
    let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
    let account = accounts_with_private_key[0].account.clone();

    let mut artifacts = scarb_build.await;
    let artifact_without_can_read_nonce =
        artifacts.remove("ContractWithCanReadNonceFalse").unwrap();
    let contract_address = artifact_without_can_read_nonce
        .declare_and_deploy_and_wait_for_receipt(account.clone(), vec![], Felt::ZERO, false)
        .await;

    let read_data = ReadData::new(
        ReadVerifier::Account(VerifierAccount {
            signer_address: account.address(),
        }),
        vec![ReadType::Nonce {
            nonce: contract_address,
        }],
        ReadValidity::Block { block: 1000000 },
        provider.chain_id().await.unwrap(),
        ReadDataVersion::One,
    );
    // Using an invalid private key to sign the read data
    let signed_read_data = sign_read_data(read_data, Felt::THREE).await.unwrap();

    let global_ctx = provider.provider_to_dummy_global_context().await;
    let nonce = get_nonce(
        global_ctx,
        GetNonceParams {
            account_address: contract_address.into(),
            signed_read_data: Some(signed_read_data),
        },
    )
    .await;
    assert_matches!(nonce, Err(GetNonceError::InvalidReadSignature));
}

#[rstest]
#[tokio::test]
#[cfg(feature = "testing")]
async fn test_can_read_nonce_returns_false(
    #[future]
    #[with("src/tests/get_nonce/test_contracts")]
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
    let artifact_without_can_read_nonce =
        artifacts.remove("ContractWithCanReadNonceFalse").unwrap();
    let address = artifact_without_can_read_nonce
        .declare_and_deploy_and_wait_for_receipt(
            account_with_private_key.account.clone(),
            vec![],
            Felt::ZERO,
            false,
        )
        .await;

    let global_ctx = provider.provider_to_dummy_global_context().await;
    let read_data = ReadData::new(
        ReadVerifier::Account(VerifierAccount {
            signer_address: account_with_private_key.account.address(),
        }),
        vec![ReadType::Nonce { nonce: address }],
        ReadValidity::Block { block: 1000000 },
        provider.chain_id().await.unwrap(),
        ReadDataVersion::One,
    );
    let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
        .await
        .unwrap();

    let nonce = get_nonce(
        global_ctx,
        GetNonceParams {
            account_address: address.into(),
            signed_read_data: Some(signed_read_data),
        },
    )
    .await;
    assert_matches!(nonce, Err(GetNonceError::NonceReadNotAllowed));
}

#[rstest]
#[tokio::test]
#[cfg(feature = "testing")]
async fn test_can_read_nonce_only_owner(
    #[future]
    #[with("src/tests/get_nonce/test_contracts")]
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
    let owner_account_with_private_key = &accounts_with_private_key[0];

    let mut artifacts = scarb_build.await;
    let artifact_without_can_read_nonce = artifacts
        .remove("ContractWithCanReadNonceOnlyOwner")
        .unwrap();
    let contract_address = artifact_without_can_read_nonce
        .declare_and_deploy_and_wait_for_receipt(
            owner_account_with_private_key.account.clone(),
            vec![],
            Felt::ZERO,
            false,
        )
        .await;

    let global_ctx = provider.provider_to_dummy_global_context().await;
    let read_data = ReadData::new(
        ReadVerifier::Account(VerifierAccount {
            signer_address: owner_account_with_private_key.account.address(),
        }),
        vec![ReadType::Nonce {
            nonce: contract_address,
        }],
        ReadValidity::Block { block: 1000000 },
        provider.chain_id().await.unwrap(),
        ReadDataVersion::One,
    );

    // Nonce with owner account should work
    let signed_read_data = sign_read_data(
        read_data.clone(),
        owner_account_with_private_key.private_key,
    )
    .await
    .unwrap();
    let nonce = get_nonce(
        global_ctx.clone(),
        GetNonceParams {
            account_address: contract_address.into(),
            signed_read_data: Some(signed_read_data),
        },
    )
    .await
    .unwrap();
    assert_eq!(nonce, GetNonceResult { nonce: 0 });

    // Nonce with other account should not work
    let other_account_with_private_key = &accounts_with_private_key[1];
    let read_data = ReadData::new(
        ReadVerifier::Account(VerifierAccount {
            signer_address: other_account_with_private_key.account.address(),
        }),
        vec![ReadType::Nonce {
            nonce: contract_address,
        }],
        ReadValidity::Block { block: 1000000 },
        provider.chain_id().await.unwrap(),
        ReadDataVersion::One,
    );
    let signed_read_data = sign_read_data(read_data, other_account_with_private_key.private_key)
        .await
        .unwrap();
    let nonce = get_nonce(
        global_ctx,
        GetNonceParams {
            account_address: contract_address.into(),
            signed_read_data: Some(signed_read_data),
        },
    )
    .await;
    assert_matches!(nonce, Err(GetNonceError::NonceReadNotAllowed));
}

#[rstest]
#[tokio::test]
#[cfg(feature = "testing")]
async fn test_get_nonce_missing_required_read_type(
    #[future]
    #[with("src/tests/get_nonce/test_contracts")]
    scarb_build: ArtifactsMap,
    #[future] madara_node_with_accounts: (
        MadaraRunner,
        Arc<StarknetProvider>,
        Vec<StarknetWalletWithPrivateKey>,
    ),
) {
    use units_primitives::read_data::ReadDataError;

    let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
    let account_with_private_key = &accounts_with_private_key[0];

    let mut artifacts = scarb_build.await;
    let artifact = artifacts
        .remove("ContractWithCanReadNonceOnlyOwner")
        .unwrap();
    let contract_address = artifact
        .declare_and_deploy_and_wait_for_receipt(
            account_with_private_key.account.clone(),
            vec![],
            Felt::ZERO,
            false,
        )
        .await;

    // Create a read data without nonce read type (use transaction receipt instead)
    let read_data = ReadData::new(
        ReadVerifier::Account(VerifierAccount {
            signer_address: account_with_private_key.account.address(),
        }),
        vec![ReadType::TransactionReceipt {
            transaction_hash: Felt::ONE,
        }], // Different type than what's needed
        ReadValidity::Block { block: 1000000 },
        provider.chain_id().await.unwrap(),
        ReadDataVersion::One,
    );

    let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
        .await
        .unwrap();

    let global_ctx = provider.provider_to_dummy_global_context().await;

    let nonce = get_nonce(
        global_ctx.clone(),
        GetNonceParams {
            account_address: contract_address.into(),
            signed_read_data: Some(signed_read_data),
        },
    )
    .await;

    assert_matches!(
        nonce,
        Err(GetNonceError::ReadSignatureError(
            ReadDataError::MissingRequiredReadTypes
        ))
    );
}
