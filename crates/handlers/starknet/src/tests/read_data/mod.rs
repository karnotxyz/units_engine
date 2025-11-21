use assert_matches::assert_matches;
use rstest::*;
use starknet::{
    accounts::Account,
    core::types::{BlockId, BlockTag, BlockWithTxHashes, MaybePreConfirmedBlockWithTxHashes},
};

use crate::tests::utils::{
    madara::{madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey},
    scarb::{scarb_build, ArtifactsMap},
};
use crate::utils::WaitForReceipt;
use crate::StarknetProvider;
use starknet::macros::selector;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
#[cfg(feature = "testing")]
use units_primitives::read_data::{
    sign_read_data, ReadData, ReadDataVersion, ReadType, ReadValidity,
};
use units_primitives::read_data::{ReadDataError, ReadVerifier, VerifierAccount, VerifierIdentity};

use starknet::core::types::Call;
use starknet::core::types::Felt;
use starknet::providers::Provider;

use crate::tests::utils::starknet::ProviderToDummyGlobalContext;

#[cfg(feature = "testing")]
mod tests {
    use super::*;
    #[rstest]
    #[tokio::test]
    async fn test_verify_success(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let global_ctx = provider.provider_to_dummy_global_context().await;
        let account_with_private_key = &accounts_with_private_key[0];

        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                signer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: Felt::from_hex_unchecked("0x0"),
            }],
            ReadValidity::Block { block: 1000000 }, // Set a high block number to avoid expiry
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let result = signed_read_data.verify(global_ctx.handler(), vec![]).await;
        assert_matches!(result, Ok(true));
    }

    #[rstest]
    #[tokio::test]
    async fn test_verify_invalid_signature(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let global_ctx = provider.provider_to_dummy_global_context().await;
        let account_with_private_key = &accounts_with_private_key[0];

        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                signer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: Felt::from_hex_unchecked("0x0"),
            }],
            ReadValidity::Block { block: 1000000 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );

        // Sign with an invalid private key (Felt::THREE)
        let signed_read_data = sign_read_data(read_data, Felt::THREE).await.unwrap();

        let result = signed_read_data.verify(global_ctx.handler(), vec![]).await;
        assert_matches!(result, Ok(false));
    }

    #[rstest]
    #[tokio::test]
    async fn test_verify_expired_timestamp(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let global_ctx = provider.provider_to_dummy_global_context().await;
        let account_with_private_key = &accounts_with_private_key[0];

        // Set timestamp to a past time
        let expired_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 1000; // 1000 seconds in the past

        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                signer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: Felt::from_hex_unchecked("0x0"),
            }],
            ReadValidity::Timestamp {
                timestamp: expired_timestamp,
            },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let result = signed_read_data.verify(global_ctx.handler(), vec![]).await;
        assert_matches!(result, Err(ReadDataError::SignatureExpired));
    }

    #[rstest]
    #[tokio::test]
    async fn test_verify_expired_block(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let global_ctx = provider.provider_to_dummy_global_context().await;
        let account_with_private_key = &accounts_with_private_key[0];

        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                signer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: Felt::from_hex_unchecked("0x0"),
            }],
            ReadValidity::Block { block: 1 },
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );

        wait_for_block(provider.clone(), 2, None).await.unwrap();

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let result = signed_read_data.verify(global_ctx.handler(), vec![]).await;
        assert_matches!(result, Err(ReadDataError::SignatureExpired));
    }

    async fn wait_for_block(
        provider: Arc<StarknetProvider>,
        block_number: u64,
        timeout: Option<Duration>,
    ) -> anyhow::Result<BlockWithTxHashes> {
        let start_time = Instant::now();
        let timeout = timeout.unwrap_or(Duration::from_secs(10));
        let retry_delay = Duration::from_millis(200);

        loop {
            match provider
                .get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest))
                .await
            {
                Ok(block) => match block {
                    MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(_) => {
                        unreachable!("Asked for latest but received pending block")
                    }
                    MaybePreConfirmedBlockWithTxHashes::Block(block) => {
                        if block.block_number >= block_number {
                            return Ok(block);
                        }
                        if start_time.elapsed() >= timeout {
                            anyhow::bail!("Block not found after {:?} timeout", timeout);
                        }
                        tokio::time::sleep(retry_delay).await;
                        continue;
                    }
                },
                Err(err) => return Err(err.into()),
            }
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_verify_identity(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
        #[future]
        #[with("src/tests/read_data/test_contracts")]
        scarb_build: ArtifactsMap,
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let global_ctx = provider.provider_to_dummy_global_context().await;
        let account_with_private_key = &accounts_with_private_key[0];

        // Get OnchainIDMock contract artifacts
        let mut artifacts = scarb_build.await;
        let onchain_id_contract = artifacts.remove("OnchainIDMock").unwrap();

        // Deploy the OnchainIDMock contract
        let identity_address = onchain_id_contract
            .declare_and_deploy_and_wait_for_receipt(
                account_with_private_key.account.clone(),
                vec![],
                Felt::ONE, // Using a non-zero salt for deployment
                true,      // Make the address unique
            )
            .await;

        // 1. Create a read data with Identity verification but don't link account yet
        let read_data = ReadData::new(
            ReadVerifier::Identity(VerifierIdentity {
                signer_address: account_with_private_key.account.address(),
                identity_address,
            }),
            vec![ReadType::Nonce {
                nonce: Felt::from_hex_unchecked("0x0"),
            }],
            ReadValidity::Block { block: 1000000 }, // Set a high block number to avoid expiry
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );

        // 2. Sign the read data
        let signed_read_data =
            sign_read_data(read_data.clone(), account_with_private_key.private_key)
                .await
                .unwrap();

        // 3. Try to verify - should fail because account is not linked to identity
        let result = signed_read_data.verify(global_ctx.handler(), vec![]).await;
        assert_matches!(result, Err(ReadDataError::InvalidIdentityKey));

        // 4. Now link the account to the identity by setting the key
        // Constants from the Cairo contract
        let key_type = Felt::from(1); // Standard key type
        let purpose = Felt::from(1); // Standard purpose

        // Call set_key on the identity contract
        let account_address = account_with_private_key.account.address();
        let set_key_result = account_with_private_key
            .account
            .execute_v3(vec![Call {
                to: identity_address,
                selector: selector!("set_key"),
                calldata: vec![
                    account_address, // key
                    key_type,        // key_type
                    purpose,         // purposes
                ],
            }])
            .send()
            .await
            .unwrap();

        // Wait for the transaction to be mined
        set_key_result
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();

        // 5. Try to verify again - should succeed now
        let result = signed_read_data.verify(global_ctx.handler(), vec![]).await;
        assert_matches!(result, Ok(true));
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_verify_with_required_read_types_success(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let global_ctx = provider.provider_to_dummy_global_context().await;
        let account_with_private_key = &accounts_with_private_key[0];

        // Create read data with two read types
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                signer_address: account_with_private_key.account.address(),
            }),
            vec![
                ReadType::Nonce {
                    nonce: Felt::from_hex_unchecked("0x0"),
                },
                ReadType::TransactionReceipt {
                    transaction_hash: Felt::from_hex_unchecked("0x1"),
                },
            ],
            ReadValidity::Block { block: 1000000 }, // Set a high block number to avoid expiry
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        // Verify with one required read type
        let result = signed_read_data
            .verify(
                global_ctx.handler(),
                vec![ReadType::Nonce {
                    nonce: Felt::from_hex_unchecked("0x0"),
                }],
            )
            .await;
        assert_matches!(result, Ok(true));

        // Verify with both required read types
        let result = signed_read_data
            .verify(
                global_ctx.handler(),
                vec![
                    ReadType::Nonce {
                        nonce: Felt::from_hex_unchecked("0x0"),
                    },
                    ReadType::TransactionReceipt {
                        transaction_hash: Felt::from_hex_unchecked("0x1"),
                    },
                ],
            )
            .await;
        assert_matches!(result, Ok(true));
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_verify_with_required_read_types_missing_type(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let global_ctx = provider.provider_to_dummy_global_context().await;
        let account_with_private_key = &accounts_with_private_key[0];

        // Create read data with one read type
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                signer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: Felt::from_hex_unchecked("0x0"),
            }],
            ReadValidity::Block { block: 1000000 }, // Set a high block number to avoid expiry
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        // Verify with a required read type that doesn't exist in the read data
        let result = signed_read_data
            .verify(
                global_ctx.handler(),
                vec![ReadType::TransactionReceipt {
                    transaction_hash: Felt::from_hex_unchecked("0x1"),
                }],
            )
            .await;
        assert_matches!(result, Err(ReadDataError::MissingRequiredReadTypes));
    }

    #[rstest]
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_verify_with_required_read_types_different_value(
        #[future] madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts_with_private_key) = madara_node_with_accounts.await;
        let global_ctx = provider.provider_to_dummy_global_context().await;
        let account_with_private_key = &accounts_with_private_key[0];

        // Create read data with a nonce read type for address ZERO
        let read_data = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                signer_address: account_with_private_key.account.address(),
            }),
            vec![ReadType::Nonce {
                nonce: Felt::from_hex_unchecked("0x0"),
            }],
            ReadValidity::Block { block: 1000000 }, // Set a high block number to avoid expiry
            provider.chain_id().await.unwrap(),
            ReadDataVersion::One,
        );

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        // Verify with a nonce read type but for a different address
        let result = signed_read_data
            .verify(
                global_ctx.handler(),
                vec![ReadType::Nonce {
                    nonce: Felt::from_hex_unchecked("0x1"),
                }],
            )
            .await;
        assert_matches!(result, Err(ReadDataError::MissingRequiredReadTypes));
    }
}
