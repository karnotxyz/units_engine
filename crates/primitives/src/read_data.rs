use std::sync::Arc;

use starknet::{
    core::types::{BlockId, BlockTag, Felt, FunctionCall, MaybePendingBlockWithTxs},
    macros::selector,
    providers::{Provider, ProviderError},
};
use starknet_crypto::poseidon_hash_many;
use units_utils::starknet::StarknetProvider;

const IS_VALID_SIGNATURE_SELECTOR: Felt = selector!("is_valid_signature");

// TODO: Add extensive testing for verify
// TODO: Add version checks

#[derive(Debug, thiserror::Error)]
pub enum ReadDataError {
    #[error("Invalid return type for is_valid_signature")]
    InvalidReturnTypeForIsValidSignature,
    #[error("Starknet error: {0}")]
    StarknetError(#[from] ProviderError),
    #[error("Signature has expired")]
    SignatureExpired,
    #[error("Asked for pending block, but got latest block")]
    UnexpectedLatestBlockInsteadOfPending,
}

#[derive(Debug, Clone)]
pub struct ReadData {
    contract_address: Felt,
    read_type: ReadType,
    read_validity: ReadValidity,
    chain_id: Felt,
    version: ReadDataVersion,
}

impl ReadData {
    pub fn new(
        contract_address: Felt,
        read_type: ReadType,
        read_validity: ReadValidity,
        chain_id: Felt,
        version: ReadDataVersion,
    ) -> Self {
        Self {
            contract_address,
            read_type,
            read_validity,
            chain_id,
            version,
        }
    }

    pub fn contract_address(&self) -> &Felt {
        &self.contract_address
    }

    pub fn read_type(&self) -> &ReadType {
        &self.read_type
    }
}

#[derive(Clone, Debug)]
pub enum ReadType {
    // stores contract address
    Nonce(Felt),
    // stores transaction hash
    TransactionReceiptEvents(Felt),
}

impl ReadType {
    fn hash(&self) -> Felt {
        match self {
            ReadType::Nonce(address) => poseidon_hash_many(vec![
                &Felt::from_hex_unchecked(hex::encode("nonce").as_str()),
                &address,
            ]),
            ReadType::TransactionReceiptEvents(hash) => poseidon_hash_many(vec![
                &Felt::from_hex_unchecked(hex::encode("transaction_receipt_events").as_str()),
                &hash,
            ]),
        }
    }
}

#[derive(Clone, Debug)]
pub enum ReadDataVersion {
    ONE,
}

impl ReadDataVersion {
    fn hash(&self) -> Felt {
        let version_felt = match self {
            ReadDataVersion::ONE => Felt::from(1),
        };
        poseidon_hash_many(vec![
            &Felt::from_hex_unchecked(hex::encode("version").as_str()),
            &version_felt,
        ])
    }
}

#[derive(Clone, Debug)]
pub enum ReadValidity {
    Block(u64),
    Timestamp(u64),
}

impl ReadValidity {
    fn hash(&self) -> Felt {
        match self {
            ReadValidity::Block(block) => poseidon_hash_many(vec![
                &Felt::from_hex_unchecked(hex::encode("block").as_str()),
                &Felt::from(*block),
            ]),
            ReadValidity::Timestamp(timestamp) => poseidon_hash_many(vec![
                &Felt::from_hex_unchecked(hex::encode("timestamp").as_str()),
                &Felt::from(*timestamp),
            ]),
        }
    }
}

impl ReadData {
    pub fn hash(&self) -> Felt {
        let mut hasher = starknet_crypto::PoseidonHasher::new();
        hasher.update(self.contract_address);
        // safe because we know the string is valid
        hasher.update(Felt::from_hex_unchecked(
            hex::encode("read_string").as_str(),
        ));
        hasher.update(self.read_type.hash());
        hasher.update(self.read_validity.hash());
        hasher.update(self.chain_id);
        hasher.update(self.version.hash());
        hasher.finalize()
    }
}

pub struct SignedReadData {
    read_data: ReadData,
    signature: Vec<Felt>,
}

impl SignedReadData {
    pub fn new(read_data: ReadData, signature: Vec<Felt>) -> Self {
        Self {
            read_data,
            signature,
        }
    }

    pub fn read_data(&self) -> &ReadData {
        &self.read_data
    }

    pub async fn verify(
        &self,
        starknet_provider: Arc<StarknetProvider>,
    ) -> Result<bool, ReadDataError> {
        // Check for expiry
        match &self.read_data.read_validity {
            ReadValidity::Block(expiry_block) => {
                // TODO: there could be an optimisation here to do a multicall that calls
                // is_valid_signature and then calls a function to check signature block_number
                // is less than equal to expiry_block
                let current_block = starknet_provider
                    .get_block_with_txs(BlockId::Tag(BlockTag::Latest))
                    .await?;
                match current_block {
                    MaybePendingBlockWithTxs::Block(block) => {
                        // do +1 to get pending block number
                        if block.block_number + 1 > *expiry_block {
                            return Err(ReadDataError::SignatureExpired);
                        }
                    }
                    MaybePendingBlockWithTxs::PendingBlock(_) => {
                        return Err(ReadDataError::UnexpectedLatestBlockInsteadOfPending);
                    }
                }
            }
            ReadValidity::Timestamp(expiry_timestamp) => {
                let current_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if current_timestamp > *expiry_timestamp {
                    return Err(ReadDataError::SignatureExpired);
                }
            }
        }

        // Verify signature
        let is_signature_valid = starknet_provider
            .call(
                FunctionCall {
                    contract_address: self.read_data.contract_address,
                    entry_point_selector: IS_VALID_SIGNATURE_SELECTOR,
                    calldata: [
                        vec![self.read_data.hash(), self.signature.len().into()],
                        self.signature.clone(),
                    ]
                    .concat(),
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await?;

        if is_signature_valid.len() > 1 {
            return Err(ReadDataError::InvalidReturnTypeForIsValidSignature);
        }

        // VALID in hex is 0x56414c4944
        Ok(is_signature_valid[0] == Felt::from_hex_unchecked("0x56414c4944"))
    }
}

// Added this here instead of in test-utils because importing primitives in test-utils
// causes a circular dependency with an error
// the crate `units_primitives` is compiled multiple times, possibly with different configurations
#[cfg(any(test, feature = "testing"))]
pub async fn sign_read_data(
    read_data: ReadData,
    private_key: Felt,
) -> anyhow::Result<SignedReadData> {
    use starknet::signers::{LocalWallet, Signer, SigningKey};

    let signer = Arc::new(LocalWallet::from(SigningKey::from_secret_scalar(
        private_key,
    )));

    let signature = signer.sign_hash(&read_data.hash()).await?;

    Ok(SignedReadData::new(
        read_data,
        vec![signature.r, signature.s],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use rstest::*;
    use starknet::{
        accounts::Account,
        core::types::{BlockWithTxHashes, MaybePendingBlockWithTxHashes},
    };
    use std::{future, sync::Arc, time::Duration};
    use units_tests_utils::madara::{
        madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey,
    };

    #[test]
    fn test_hash_nonce() {
        let read_signature = ReadData::new(
            Felt::from_hex_unchecked("0x5"),
            ReadType::Nonce(Felt::from_hex_unchecked("0x1")),
            ReadValidity::Block(100),
            Felt::from_hex_unchecked("0x3"),
            ReadDataVersion::ONE,
        );
        assert_eq!(
            read_signature.hash(),
            poseidon_hash_many(vec![
                // contract_address
                &Felt::from_hex_unchecked("0x5"),
                // read_string
                &Felt::from_hex_unchecked("0x726561645f737472696e67"),
                // nonce
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x6e6f6e6365"),
                    &Felt::from_hex_unchecked("0x1"),
                ]),
                // valid_until_block
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x626c6f636b"),
                    &Felt::from(100),
                ]),
                // chain_id
                &Felt::from_hex_unchecked("0x3"),
                // version
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x76657273696f6e"),
                    &Felt::from(1),
                ]),
            ])
        );
    }

    #[test]
    fn test_hash_nonce_timestamp() {
        let read_signature = ReadData::new(
            Felt::from_hex_unchecked("0x5"),
            ReadType::Nonce(Felt::from_hex_unchecked("0x1")),
            ReadValidity::Timestamp(100),
            Felt::from_hex_unchecked("0x3"),
            ReadDataVersion::ONE,
        );
        assert_eq!(
            read_signature.hash(),
            poseidon_hash_many(vec![
                // contract_address
                &Felt::from_hex_unchecked("0x5"),
                // read_string
                &Felt::from_hex_unchecked("0x726561645f737472696e67"),
                // nonce
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x6e6f6e6365"),
                    &Felt::from(1),
                ]),
                // valid_until_block
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x74696d657374616d70"),
                    &Felt::from(100),
                ]),
                // chain_id
                &Felt::from_hex_unchecked("0x3"),
                // version
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x76657273696f6e"),
                    &Felt::from(1),
                ]),
            ])
        );
    }

    #[test]
    fn test_hash_transaction_receipt_events() {
        let read_signature = ReadData::new(
            Felt::from_hex_unchecked("0x5"),
            ReadType::TransactionReceiptEvents(Felt::from_hex_unchecked("0x123")),
            ReadValidity::Block(100),
            Felt::from_hex_unchecked("0x356"),
            ReadDataVersion::ONE,
        );
        assert_eq!(
            read_signature.hash(),
            poseidon_hash_many(vec![
                // contract_address
                &Felt::from_hex_unchecked("0x5"),
                // read_string
                &Felt::from_hex_unchecked("0x726561645f737472696e67"),
                // transaction_receipt_events
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked(
                        "0x7472616e73616374696f6e5f726563656970745f6576656e7473"
                    ),
                    &Felt::from_hex_unchecked("0x123"),
                ]),
                // valid_until_block
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x626c6f636b"),
                    &Felt::from(100),
                ]),
                // chain_id
                &Felt::from_hex_unchecked("0x356"),
                // version
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x76657273696f6e"),
                    &Felt::from(1),
                ]),
            ])
        );
    }

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
        let account_with_private_key = &accounts_with_private_key[0];

        let read_data = ReadData::new(
            account_with_private_key.account.address(),
            ReadType::Nonce(Felt::ZERO),
            ReadValidity::Block(1000000), // Set a high block number to avoid expiry
            provider.chain_id().await.unwrap(),
            ReadDataVersion::ONE,
        );

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let result = signed_read_data.verify(provider).await;
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
        let account_with_private_key = &accounts_with_private_key[0];

        let read_data = ReadData::new(
            account_with_private_key.account.address(),
            ReadType::Nonce(Felt::ZERO),
            ReadValidity::Block(1000000),
            provider.chain_id().await.unwrap(),
            ReadDataVersion::ONE,
        );

        // Sign with an invalid private key (Felt::THREE)
        let signed_read_data = sign_read_data(read_data, Felt::THREE).await.unwrap();

        let result = signed_read_data.verify(provider).await;
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
        let account_with_private_key = &accounts_with_private_key[0];

        // Set timestamp to a past time
        let expired_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 1000; // 1000 seconds in the past

        let read_data = ReadData::new(
            account_with_private_key.account.address(),
            ReadType::Nonce(Felt::ZERO),
            ReadValidity::Timestamp(expired_timestamp),
            provider.chain_id().await.unwrap(),
            ReadDataVersion::ONE,
        );

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let result = signed_read_data.verify(provider).await;
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
        let account_with_private_key = &accounts_with_private_key[0];

        let read_data = ReadData::new(
            account_with_private_key.account.address(),
            ReadType::Nonce(Felt::ZERO),
            ReadValidity::Block(1),
            provider.chain_id().await.unwrap(),
            ReadDataVersion::ONE,
        );

        wait_for_block(provider.clone(), 2, None).await.unwrap();

        let signed_read_data = sign_read_data(read_data, account_with_private_key.private_key)
            .await
            .unwrap();

        let result = signed_read_data.verify(provider).await;
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
                    MaybePendingBlockWithTxHashes::PendingBlock(_) => {
                        unreachable!("Asked for latest but received pending block")
                    }
                    MaybePendingBlockWithTxHashes::Block(block) => {
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
}
