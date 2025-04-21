use std::sync::Arc;

use jsonrpsee::core::params;
use starknet::core::types::{BlockId, BlockTag, Call, ContractClass, Felt, FunctionCall};
use starknet::macros::selector;
use starknet::providers::{Provider, ProviderError};
use units_primitives::context::{ChainHandlerError, GlobalContext};
use units_primitives::read_data::{ReadDataError, ReadType, SignedReadData};
use units_primitives::rpc::{GetClassParams, GetProgramResult, HexBytes32Error};
use units_primitives::types::{ClassVisibility, ClassVisibilityError};

pub const HAS_READ_ACCESS_FUNCTION_NAME: &str = "has_read_access";
/// If the public address has access then it's assumed that the contract is public
/// and any address can read it
pub const PUBLIC_ACCESS_ADDRESS: Felt = Felt::ZERO;

#[derive(Debug, thiserror::Error)]
pub enum GetClassError {
    #[error("Starknet error: {0}")]
    StarknetError(#[from] ProviderError),
    #[error("Read signature not provided")]
    ReadSignatureNotProvided,
    #[error("Class read not allowed")]
    ClassReadNotAllowed,
    #[error("Invalid class visibility")]
    InvalidClassVisibility(#[from] ClassVisibilityError),
    #[error("Read data error: {0}")]
    ReadDataError(#[from] ReadDataError),
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
    #[error("HexBytes32 error: {0}")]
    HexBytes32Error(#[from] HexBytes32Error),
}

pub async fn get_class(
    global_ctx: Arc<GlobalContext>,
    params: GetClassParams,
    signed_read_data: Option<SignedReadData>,
) -> Result<GetProgramResult, GetClassError> {
    let handler = global_ctx.handler();

    // Check if the contract is public
    let visibility: ClassVisibility = handler.get_class_visibility(params.class_hash).await?;

    if visibility != ClassVisibility::Public {
        // Check if user has access to the contract
        let signed_read_data = signed_read_data.ok_or(GetClassError::ReadSignatureNotProvided)?;

        // Verify the signature and check that it has the required read type
        if !signed_read_data
            .verify(
                handler.clone(),
                vec![ReadType::Class {
                    class_hash: params.class_hash.try_into()?,
                }],
            )
            .await
            .map_err(GetClassError::ReadDataError)?
        {
            return Err(GetClassError::ClassReadNotAllowed);
        }

        let has_read_access = handler
            .simulate_read_access_check(
                signed_read_data.read_data().read_address().clone().into(),
                handler.get_declare_acl_address(),
                HAS_READ_ACCESS_FUNCTION_NAME.to_string(),
                vec![params.class_hash],
            )
            .await?;

        if !has_read_access {
            return Err(GetClassError::ClassReadNotAllowed);
        }
    }

    let class = handler.get_program(params.class_hash).await?;
    Ok(class)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::WaitForReceipt;
    use crate::StarknetProvider;
    use assert_matches::assert_matches;
    use rstest::*;
    use starknet::accounts::Account;
    #[cfg(feature = "testing")]
    use units_primitives::read_data::sign_read_data;
    use units_primitives::read_data::{ReadData, ReadDataVersion, ReadType, ReadValidity};
    use units_primitives::read_data::{ReadVerifier, VerifierAccount};
    use units_tests_utils::{
        madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
        scarb::{scarb_build, ArtifactsMap},
    };

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_get_class(
        #[future]
        #[with("src/get_class/test_contracts")]
        scarb_build: ArtifactsMap,
        #[future]
        #[with(2)]
        madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        use units_tests_utils::starknet::assert_contract_class_eq;

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
        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider.clone(),
            declare_acl_address,
            accounts_with_private_key[0].account.clone(),
        ));

        // Declare a dummy contract for us to get via get_class
        let dummy_contract_artifact = artifacts.remove("EmptyContract").unwrap();
        let (dummy_contract_class_hash, _) = dummy_contract_artifact
            .clone()
            .declare_and_wait_for_receipt(owner_account_with_private_key.account.clone())
            .await;

        // As we're directly calling Madara and not going via the Units RPC,
        // the DeclareAcl contract is not updated and by default the contract visibility is private
        // i.e. Acl driven. This is just for this test contract, actual implementation could differ.
        let class = get_class(starknet_ctx.clone(), dummy_contract_class_hash, None).await;
        assert_matches!(class, Err(GetClassError::ReadSignatureNotProvided));

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
        let class = get_class(starknet_ctx.clone(), dummy_contract_class_hash, None).await;
        assert_contract_class_eq(
            dummy_contract_artifact
                .clone()
                .contract_class
                .flatten()
                .unwrap(),
            class.unwrap(),
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
                class_hash: dummy_contract_class_hash.into(),
            }],
            ReadValidity::Block { block: 100 },
            chain_id,
            ReadDataVersion::One,
        );
        let signed_read_data = sign_read_data(read_data, accounts_with_private_key[1].private_key)
            .await
            .unwrap();
        let class = get_class(
            starknet_ctx.clone(),
            dummy_contract_class_hash,
            Some(signed_read_data.clone()),
        )
        .await;
        assert_matches!(class, Err(GetClassError::ClassReadNotAllowed));

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
        let class = get_class(
            starknet_ctx.clone(),
            dummy_contract_class_hash,
            Some(signed_read_data),
        )
        .await;
        assert_contract_class_eq(
            dummy_contract_artifact
                .clone()
                .contract_class
                .flatten()
                .unwrap(),
            class.unwrap(),
        );

        // Try to access with a signed read data for a different class hash
        let different_class_hash = Felt::from_hex_unchecked("0x123");
        let read_data_with_different_class = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: accounts_with_private_key[1].account.address(),
            }),
            vec![ReadType::Class {
                class_hash: different_class_hash.into(),
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
        let class = get_class(
            starknet_ctx,
            dummy_contract_class_hash,
            Some(signed_read_data_with_different_class),
        )
        .await;
        assert_matches!(
            class,
            Err(GetClassError::ReadDataError(
                ReadDataError::MissingRequiredReadTypes
            ))
        );
    }
}
