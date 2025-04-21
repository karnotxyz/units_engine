use std::sync::Arc;

use starknet::{
    core::types::{BlockId, Call, Felt, StarknetError},
    providers::{Provider, ProviderError},
};
use units_primitives::{
    context::{ChainHandlerError, GlobalContext},
    read_data::{ReadDataError, ReadType, SignedReadData},
    rpc::{GetNonceParams, GetNonceResult, HexBytes32, HexBytes32Error},
};

const CAN_READ_NONCE_FUNCTION_NAME: &str = "can_read_nonce";

#[derive(Debug, thiserror::Error)]
pub enum NonceError {
    #[error("Read signature not provided")]
    ReadSignatureNotProvided,
    #[error("Failed to read execution result")]
    FailedExecutionResultRead(anyhow::Error),
    #[error("Empty can get nonce read result")]
    EmptyCanGetNonceReadResult,
    #[error("Nonce read not allowed")]
    NonceReadNotAllowed,
    #[error("Read Data Error: {0}")]
    ReadSignatureError(#[from] ReadDataError),
    #[error("Invalid read signature")]
    InvalidReadSignature,
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
    #[error("HexBytes32 error: {0}")]
    HexBytes32Error(#[from] HexBytes32Error),
}

pub async fn get_nonce(
    global_ctx: Arc<GlobalContext>,
    params: GetNonceParams,
) -> Result<GetNonceResult, NonceError> {
    let handler = global_ctx.handler();

    // Get contract ABI to check for `can_read_nonce` method
    let has_selector = handler
        .contract_has_function(
            params.account_address,
            CAN_READ_NONCE_FUNCTION_NAME.to_string(),
        )
        .await
        .map_err(NonceError::ChainHandlerError)?;

    if has_selector {
        // Check if the read signature is valid by calling `is_valid_signature`
        let signed_read_data = params
            .signed_read_data
            .ok_or(NonceError::ReadSignatureNotProvided)?;

        // Verify the signature and check that it has the required read type
        if !signed_read_data
            .verify(
                handler.clone(),
                vec![ReadType::Nonce {
                    nonce: params.account_address.try_into()?,
                }],
            )
            .await?
        {
            return Err(NonceError::InvalidReadSignature);
        }

        // If the signature is valid, we can now check if the account has access to read the nonce
        // So we build a simulated transaction that tries to call `can_read_nonce` on the smart contract
        // and the "sender_address" is the address of the account that is trying to read the nonce
        // If the account has access, the simulation will succeed and the result will be 0x1 (true)
        let can_read_nonce = handler
            .simulate_read_access_check(
                params.account_address,
                params.account_address,
                CAN_READ_NONCE_FUNCTION_NAME.to_string(),
                vec![],
            )
            .await?;

        if !can_read_nonce {
            return Err(NonceError::NonceReadNotAllowed);
        }
    }

    Ok(GetNonceResult {
        nonce: handler.get_nonce(params.account_address).await?,
    })
}

#[cfg(test)]
mod tests {

    use super::*;
    use assert_matches::assert_matches;
    use rstest::*;
    use starknet::{accounts::Account, core::types::BlockTag};
    #[cfg(feature = "testing")]
    use units_primitives::read_data::sign_read_data;

    use crate::{StarknetProvider, StarknetWallet};
    use units_primitives::read_data::{ReadData, ReadDataVersion, ReadType, ReadValidity};
    use units_primitives::read_data::{ReadVerifier, VerifierAccount};
    use units_tests_utils::starknet::TestDefault;
    use units_tests_utils::{
        madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
        scarb::{scarb_build, ArtifactsMap},
    };

    #[rstest]
    #[tokio::test]
    async fn test_can_read_nonce_does_not_exist(
        #[future]
        #[with("src/nonce/test_contracts")]
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
            artifacts.remove("ContractWithoutCanReadNonce").unwrap();
        let address = artifact_without_can_read_nonce
            .declare_and_deploy_and_wait_for_receipt(account, vec![], Felt::ZERO, false)
            .await;

        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider,
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let nonce = get_nonce(starknet_ctx, BlockId::Tag(BlockTag::Pending), address, None)
            .await
            .unwrap();
        assert_eq!(nonce, Felt::ZERO);
    }

    #[rstest]
    #[tokio::test]
    async fn test_can_read_nonce_returns_without_read_data(
        #[future]
        #[with("src/nonce/test_contracts")]
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

        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider,
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let nonce = get_nonce(starknet_ctx, BlockId::Tag(BlockTag::Pending), address, None).await;
        assert_matches!(nonce, Err(NonceError::ReadSignatureNotProvided));
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_can_read_nonce_returns_invalid_read_signature(
        #[future]
        #[with("src/nonce/test_contracts")]
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
                singer_address: account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: contract_address.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        // Using an invalid private key to sign the read data
        let signed_read_data = sign_read_data(read_data, Felt::THREE).await.unwrap();

        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider,
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let nonce = get_nonce(
            starknet_ctx,
            BlockId::Tag(BlockTag::Pending),
            contract_address,
            Some(signed_read_data),
        )
        .await;
        assert_matches!(nonce, Err(NonceError::InvalidReadSignature));
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_can_read_nonce_returns_false(
        #[future]
        #[with("src/nonce/test_contracts")]
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

        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider.clone(),
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: address.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let nonce = get_nonce(
            starknet_ctx,
            BlockId::Tag(BlockTag::Pending),
            address,
            Some(signed_read_data),
        )
        .await;
        assert_matches!(nonce, Err(NonceError::NonceReadNotAllowed));
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_can_read_nonce_only_owner(
        #[future]
        #[with("src/nonce/test_contracts")]
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

        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider.clone(),
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: owner_account_with_private_key.account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: contract_address.into(),
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
            starknet_ctx.clone(),
            BlockId::Tag(BlockTag::Pending),
            contract_address,
            Some(signed_read_data),
        )
        .await
        .unwrap();
        assert_eq!(nonce, Felt::ZERO);

        // Nonce with other account should not work
        let other_account_with_private_key = &accounts_with_private_key[1];
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: other_account_with_private_key.account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: contract_address.into(),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );
        let signed_read_data =
            sign_read_data(read_data, other_account_with_private_key.private_key)
                .await
                .unwrap();
        let nonce = get_nonce(
            starknet_ctx,
            BlockId::Tag(BlockTag::Pending),
            contract_address,
            Some(signed_read_data),
        )
        .await;
        assert_matches!(nonce, Err(NonceError::NonceReadNotAllowed));
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_get_nonce_missing_required_read_type(
        #[future]
        #[with("src/nonce/test_contracts")]
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
                singer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::TransactionReceipt {
                transaction_hash: Felt::ONE.into(),
            }], // Different type than what's needed
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let starknet_ctx = Arc::new(StarknetContext::new_with_provider(
            provider,
            Felt::ONE,
            Arc::new(StarknetWallet::test_default()),
        ));

        let nonce = get_nonce(
            starknet_ctx,
            BlockId::Tag(BlockTag::Pending),
            contract_address,
            Some(signed_read_data),
        )
        .await;

        assert_matches!(
            nonce,
            Err(NonceError::ReadSignatureError(
                ReadDataError::MissingRequiredReadTypes
            ))
        );
    }
}
