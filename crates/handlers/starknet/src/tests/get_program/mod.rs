use assert_matches::assert_matches;
use rstest::*;
use starknet::accounts::Account;

use crate::tests::utils::{
    madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
    scarb::{scarb_build, ArtifactsMap},
};
use crate::utils::WaitForReceipt;
use crate::StarknetProvider;
use starknet::macros::selector;
use std::sync::Arc;
#[cfg(feature = "testing")]
use units_primitives::read_data::{
    sign_read_data, ReadData, ReadDataVersion, ReadType, ReadValidity,
};
use units_primitives::read_data::{ReadVerifier, VerifierAccount};

use starknet::core::types::Call;
use starknet::core::types::Felt;
use starknet::providers::Provider;

#[rstest]
#[tokio::test]
#[cfg(feature = "testing")]
async fn test_get_program(
    #[future]
    #[with("src/tests/get_program/test_contracts")]
    scarb_build: ArtifactsMap,
    #[future]
    #[with(2)]
    madara_node_with_accounts: (
        MadaraRunner,
        Arc<StarknetProvider>,
        Vec<StarknetWalletWithPrivateKey>,
    ),
) {
    use starknet::core::types::{ContractClass, FlattenedSierraClass};
    use units_handlers_common::get_program::{get_program, GetProgramError};
    use units_primitives::{
        context::GlobalContext, read_data::ReadDataError, rpc::GetProgramParams,
        types::ClassVisibility,
    };

    use crate::{tests::utils::starknet::assert_contract_class_eq, StarknetContext};

    let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
    let owner_account_with_private_key = &accounts_with_private_key[0];

    // Delcare the DeclareACL contract
    let mut artifacts = scarb_build.await;
    let declare_acl_artifact = artifacts.remove("DeclareAclContract").unwrap();
    let declare_acl_address = declare_acl_artifact
        .declare_and_deploy_and_wait_for_receipt(
            owner_account_with_private_key.account.clone(),
            vec![],
            Felt::ZERO,
            false,
        )
        .await;
    let starknet_ctx = StarknetContext::new_with_provider(
        provider.clone(),
        declare_acl_address.into(),
        owner_account_with_private_key.private_key.into(),
        owner_account_with_private_key.account.address().into(),
    )
    .await
    .unwrap();
    let global_ctx = Arc::new(GlobalContext::new(Arc::new(Box::new(starknet_ctx))));

    // Declare a dummy contract for us to get via get_program
    let dummy_contract_artifact = artifacts.remove("EmptyContract").unwrap();
    let (dummy_contract_class_hash, _) = dummy_contract_artifact
        .clone()
        .declare_and_wait_for_receipt(owner_account_with_private_key.account.clone())
        .await;

    // As we're directly calling Madara and not going via the Units RPC,
    // the DeclareAcl contract is not updated and by default the contract visibility is private
    // i.e. Acl driven. This is just for this test contract, actual implementation could differ.
    let class = get_program(
        global_ctx.clone(),
        GetProgramParams {
            class_hash: dummy_contract_class_hash.into(),
            signed_read_data: None,
        },
    )
    .await;
    assert_matches!(class, Err(GetProgramError::ReadSignatureNotProvided));

    // Make the contract visbility Public
    let owner_account = owner_account_with_private_key.account.clone();
    owner_account
        .execute_v3(vec![Call {
            to: declare_acl_address,
            selector: selector!("set_visibility"),
            calldata: vec![
                dummy_contract_class_hash,
                ClassVisibility::Public.into(),
                owner_account.address(),
            ],
        }])
        .gas(0)
        .gas_price(0)
        .send()
        .await
        .unwrap()
        .wait_for_receipt(provider.clone(), None)
        .await
        .unwrap();
    let class = get_program(
        global_ctx.clone(),
        GetProgramParams {
            class_hash: dummy_contract_class_hash.into(),
            signed_read_data: None,
        },
    )
    .await;
    let class: FlattenedSierraClass = serde_json::from_value(class.unwrap().program).unwrap();
    assert_contract_class_eq(
        dummy_contract_artifact
            .clone()
            .contract_class
            .flatten()
            .unwrap(),
        ContractClass::Sierra(class),
    );

    // Make the contract visibility ACL againowner_account
    owner_account
        .execute_v3(vec![Call {
            to: declare_acl_address,
            selector: selector!("set_visibility"),
            calldata: vec![
                dummy_contract_class_hash,
                ClassVisibility::Acl.into(),
                owner_account.address(),
            ],
        }])
        .gas(0)
        .gas_price(0)
        .send()
        .await
        .unwrap()
        .wait_for_receipt(provider.clone(), None)
        .await
        .unwrap();

    // Attempt access from 2nd account with read signature but no access
    let chain_id = provider.chain_id().await.unwrap();
    let read_data = ReadData::new(
        ReadVerifier::Account(VerifierAccount {
            singer_address: accounts_with_private_key[1].account.address(),
        }),
        vec![ReadType::Class {
            class_hash: dummy_contract_class_hash,
        }],
        ReadValidity::Block { block: 100 },
        chain_id,
        ReadDataVersion::One,
    );
    let signed_read_data = sign_read_data(read_data, accounts_with_private_key[1].private_key)
        .await
        .unwrap();
    let class = get_program(
        global_ctx.clone(),
        GetProgramParams {
            class_hash: dummy_contract_class_hash.into(),
            signed_read_data: Some(signed_read_data.clone()),
        },
    )
    .await;
    assert_matches!(class, Err(GetProgramError::ClassReadNotAllowed));

    // Grant access to the account
    owner_account
        .execute_v3(vec![Call {
            to: declare_acl_address,
            selector: selector!("update_acl"),
            calldata: vec![
                dummy_contract_class_hash,
                accounts_with_private_key[1].account.address(),
                // true
                Felt::ONE,
                owner_account.address(),
            ],
        }])
        .gas(0)
        .gas_price(0)
        .send()
        .await
        .unwrap()
        .wait_for_receipt(provider.clone(), None)
        .await
        .unwrap();
    let class = get_program(
        global_ctx.clone(),
        GetProgramParams {
            class_hash: dummy_contract_class_hash.into(),
            signed_read_data: Some(signed_read_data),
        },
    )
    .await;
    let class: FlattenedSierraClass = serde_json::from_value(class.unwrap().program).unwrap();
    assert_contract_class_eq(
        dummy_contract_artifact
            .clone()
            .contract_class
            .flatten()
            .unwrap(),
        ContractClass::Sierra(class),
    );

    // Try to access with a signed read data for a different class hash
    let different_class_hash = Felt::from_hex_unchecked("0x123");
    let read_data_with_different_class = ReadData::new(
        ReadVerifier::Account(VerifierAccount {
            singer_address: accounts_with_private_key[1].account.address(),
        }),
        vec![ReadType::Class {
            class_hash: different_class_hash,
        }],
        ReadValidity::Block { block: 100 },
        chain_id,
        ReadDataVersion::One,
    );
    let signed_read_data_with_different_class = sign_read_data(
        read_data_with_different_class,
        accounts_with_private_key[1].private_key,
    )
    .await
    .unwrap();
    let class = get_program(
        global_ctx.clone(),
        GetProgramParams {
            class_hash: dummy_contract_class_hash.into(),
            signed_read_data: Some(signed_read_data_with_different_class),
        },
    )
    .await;
    assert_matches!(
        class,
        Err(GetProgramError::ReadDataError(
            ReadDataError::MissingRequiredReadTypes
        ))
    );
}
