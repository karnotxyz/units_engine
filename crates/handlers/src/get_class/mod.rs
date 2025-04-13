use std::sync::Arc;

use starknet::core::types::{BlockId, BlockTag, Call, ContractClass, Felt, FunctionCall};
use starknet::macros::selector;
use starknet::providers::{Provider, ProviderError};
use units_primitives::read_data::SignedReadData;
use units_utils::context::GlobalContext;
use units_utils::starknet::{
    simulate_boolean_read, simulate_boolean_read_with_nonce, SimulationError,
};

pub const HAS_READ_ACCESS_SELECTOR: Felt = selector!("has_read_access");
/// If the public address has access then it's assumed that the contract is public
/// and any address can read it
pub const PUBLIC_ACCESS_ADDRESS: Felt = Felt::ZERO;

#[derive(Debug, thiserror::Error)]
pub enum GetClassError {
    #[error("Starknet error: {0}")]
    StarknetError(#[from] ProviderError),
    #[error("Simulation error: {0}")]
    SimulationError(#[from] SimulationError),
    #[error("Read signature not provided")]
    ReadSignatureNotProvided,
    #[error("Class read not allowed")]
    ClassReadNotAllowed,
    #[error("Invalid class visibility")]
    InvalidClassVisibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassVisibility {
    Public,
    Acl,
}

impl TryFrom<Vec<Felt>> for ClassVisibility {
    type Error = GetClassError;

    fn try_from(value: Vec<Felt>) -> Result<Self, Self::Error> {
        if value.len() != 1 {
            return Err(GetClassError::InvalidClassVisibility);
        }
        let visibility = value[0];
        if visibility == Felt::ZERO {
            Ok(ClassVisibility::Public)
        } else if visibility == Felt::ONE {
            Ok(ClassVisibility::Acl)
        } else {
            Err(GetClassError::InvalidClassVisibility)
        }
    }
}

impl From<ClassVisibility> for Felt {
    fn from(value: ClassVisibility) -> Self {
        match value {
            ClassVisibility::Public => Felt::ZERO,
            ClassVisibility::Acl => Felt::ONE,
        }
    }
}
pub async fn get_class(
    global_ctx: Arc<GlobalContext>,
    class_hash: Felt,
    signed_read_data: Option<SignedReadData>,
) -> Result<ContractClass, GetClassError> {
    let starknet_provider = global_ctx.starknet_provider();

    // Check if the contract is public
    let declare_acl_address = global_ctx.declare_acl_address();
    let visibility: ClassVisibility = starknet_provider
        .call(
            FunctionCall {
                contract_address: declare_acl_address,
                entry_point_selector: selector!("get_visibility"),
                calldata: vec![class_hash],
            },
            BlockId::Tag(BlockTag::Pending),
        )
        .await
        .map_err(GetClassError::StarknetError)?
        .try_into()?;

    if visibility != ClassVisibility::Public {
        // Check if user has access to the contract
        let signed_read_data = signed_read_data.ok_or(GetClassError::ReadSignatureNotProvided)?;
        let has_read_access = simulate_boolean_read(
            vec![Call {
                to: declare_acl_address,
                selector: HAS_READ_ACCESS_SELECTOR,
                calldata: vec![class_hash],
            }],
            *signed_read_data.read_data().contract_address(),
            starknet_provider.clone(),
        )
        .await
        .map_err(GetClassError::SimulationError)?;

        if !has_read_access {
            return Err(GetClassError::ClassReadNotAllowed);
        }
    }

    let class = starknet_provider
        .get_class(BlockId::Tag(BlockTag::Pending), class_hash)
        .await
        .map_err(GetClassError::StarknetError)?;
    Ok(class)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use rstest::*;
    use starknet::{accounts::Account, core::types::FlattenedSierraClass};
    #[cfg(feature = "testing")]
    use units_primitives::read_data::sign_read_data;
    use units_primitives::read_data::{ReadData, ReadDataVersion, ReadType, ReadValidity};
    use units_tests_utils::{
        madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
        scarb::{scarb_build, ArtifactsMap},
    };
    use units_utils::starknet::{StarknetProvider, WaitForReceipt};

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
        let global_ctx = Arc::new(GlobalContext::new_with_provider(
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

        // By default, the contract is public
        let class = get_class(global_ctx.clone(), dummy_contract_class_hash, None).await;
        assert_contract_class_eq(
            dummy_contract_artifact
                .clone()
                .contract_class
                .flatten()
                .unwrap(),
            class.unwrap(),
        );

        // Make the contract visbility ACL
        let owner_account = owner_account_with_private_key.account.clone();
        let result = owner_account
            .execute_v3(vec![Call {
                to: declare_acl_address,
                selector: selector!("set_visibility"),
                calldata: vec![
                    dummy_contract_class_hash,
                    ClassVisibility::Acl.into(),
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
        let class = get_class(global_ctx.clone(), dummy_contract_class_hash, None).await;
        assert_matches!(class, Err(GetClassError::ReadSignatureNotProvided));

        // Attempt access from 2nd account with read signature but no access
        let chain_id = provider.chain_id().await.unwrap();
        let read_data = ReadData::new(
            accounts_with_private_key[1].account.address(),
            ReadType::Class(dummy_contract_class_hash),
            ReadValidity::Block(100),
            chain_id,
            ReadDataVersion::ONE,
        );
        let signed_read_data = sign_read_data(read_data, accounts_with_private_key[1].private_key)
            .await
            .unwrap();
        let class = get_class(
            global_ctx.clone(),
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
        let class = get_class(global_ctx.clone(), dummy_contract_class_hash, Some(signed_read_data)).await;
        assert_contract_class_eq(
            dummy_contract_artifact
                .clone()
                .contract_class
                .flatten()
                .unwrap(),
            class.unwrap(),
        );
    }

    fn assert_contract_class_eq(expected: FlattenedSierraClass, actual: ContractClass) {
        match actual {
            ContractClass::Sierra(actual) => {
                assert_eq!(expected, actual);
            }
            _ => panic!("Contract class is not a Sierra class"),
        }
    }
}
