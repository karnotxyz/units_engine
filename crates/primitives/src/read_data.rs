use std::sync::Arc;

use crate::context::{ChainHandler, ChainHandlerError};
use serde::{Deserialize, Serialize};
use starknet_crypto::poseidon_hash_many;
use starknet_crypto::Felt;

// TODO: Add extensive testing for verify
// TODO: Add version checks

#[derive(Debug, thiserror::Error, Serialize, PartialEq, Eq)]
pub enum ReadDataError {
    #[error("Invalid return type for is_valid_signature")]
    InvalidReturnTypeForIsValidSignature,
    #[error("Signature has expired")]
    SignatureExpired,
    #[error("Asked for pending block, but got latest block")]
    UnexpectedLatestBlockInsteadOfPending,
    #[error("Invalid key for identity")]
    InvalidIdentityKey,
    #[error("Invalid return type for get_key")]
    InvalidReturnTypeForGetKey,
    #[error("Empty key result")]
    EmptyKeyResult,
    #[error("Missing required read type permissions")]
    MissingRequiredReadTypes,
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierAccount {
    pub singer_address: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierIdentity {
    pub signer_address: Felt,
    pub identity_address: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum ReadVerifier {
    Account(VerifierAccount),
    Identity(VerifierIdentity),
}

impl ReadVerifier {
    // Returns the address that signed the read data
    pub fn signer_address(&self) -> &Felt {
        match self {
            ReadVerifier::Account(account) => &account.singer_address,
            ReadVerifier::Identity(identity) => &identity.signer_address,
        }
    }

    // Returns the address of the contract that has the read access
    pub fn read_address(&self) -> &Felt {
        match self {
            ReadVerifier::Account(account) => &account.singer_address,
            ReadVerifier::Identity(identity) => &identity.identity_address,
        }
    }

    // Returns the hash value for this address
    fn hash(&self) -> Felt {
        match self {
            ReadVerifier::Account(account) => {
                // For account, hash the type and address
                poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked(hex::encode("account").as_str()),
                    &account.singer_address,
                ])
            }
            ReadVerifier::Identity(identity) => {
                // For identity, we hash both addresses
                poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked(hex::encode("identity").as_str()),
                    &identity.signer_address,
                    &identity.identity_address,
                ])
            }
        }
    }
}

// TODO: Make ReadData generic in terms of the hasher used and the type should be HexBytes32 instead of Felt
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadData {
    verifier: ReadVerifier,
    read_type: Vec<ReadType>,
    read_validity: ReadValidity,
    chain_id: Felt,
    version: ReadDataVersion,
}

impl ReadData {
    pub fn new(
        contract_address: ReadVerifier,
        read_type: Vec<ReadType>,
        read_validity: ReadValidity,
        chain_id: Felt,
        version: ReadDataVersion,
    ) -> Self {
        Self {
            verifier: contract_address,
            read_type,
            read_validity,
            chain_id,
            version,
        }
    }

    pub fn verifier(&self) -> &ReadVerifier {
        &self.verifier
    }

    pub fn read_address(&self) -> &Felt {
        self.verifier.read_address()
    }

    pub fn singer_address(&self) -> &Felt {
        self.verifier.signer_address()
    }

    pub fn read_type(&self) -> &Vec<ReadType> {
        &self.read_type
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum ReadType {
    // stores contract address
    Nonce { nonce: Felt },
    // stores transaction hash
    TransactionReceipt { transaction_hash: Felt },
    // stores class hash
    Class { class_hash: Felt },
}

impl ReadType {
    fn hash(&self) -> Felt {
        match self {
            ReadType::Nonce { nonce } => poseidon_hash_many(vec![
                &Felt::from_hex_unchecked(hex::encode("nonce").as_str()),
                &Felt::from_bytes_be(&nonce.to_bytes_be()),
            ]),
            ReadType::TransactionReceipt {
                transaction_hash: transaction_receipt,
            } => poseidon_hash_many(vec![
                &Felt::from_hex_unchecked(hex::encode("transaction_receipt").as_str()),
                &Felt::from_bytes_be(&transaction_receipt.to_bytes_be()),
            ]),
            ReadType::Class { class_hash: class } => poseidon_hash_many(vec![
                &Felt::from_hex_unchecked(hex::encode("class").as_str()),
                &Felt::from_bytes_be(&class.to_bytes_be()),
            ]),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ReadDataVersion {
    One,
}

impl ReadDataVersion {
    fn hash(&self) -> Felt {
        let version_felt = match self {
            ReadDataVersion::One => Felt::from(1),
        };
        poseidon_hash_many(vec![
            &Felt::from_hex_unchecked(hex::encode("version").as_str()),
            &version_felt,
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum ReadValidity {
    Block { block: u64 },
    Timestamp { timestamp: u64 },
}

impl ReadValidity {
    fn hash(&self) -> Felt {
        match self {
            ReadValidity::Block { block } => poseidon_hash_many(vec![
                &Felt::from_hex_unchecked(hex::encode("block").as_str()),
                &Felt::from(*block),
            ]),
            ReadValidity::Timestamp { timestamp } => poseidon_hash_many(vec![
                &Felt::from_hex_unchecked(hex::encode("timestamp").as_str()),
                &Felt::from(*timestamp),
            ]),
        }
    }
}

impl ReadData {
    pub fn hash(&self) -> Felt {
        let mut hasher = starknet_crypto::PoseidonHasher::new();
        let read_type_hashes = self
            .read_type
            .iter()
            .map(|read_type| read_type.hash())
            .collect::<Vec<_>>();
        // safe because we know the string is valid
        hasher.update(Felt::from_hex_unchecked(
            hex::encode("read_string").as_str(),
        ));
        hasher.update(self.verifier.hash());
        hasher.update(poseidon_hash_many(read_type_hashes.iter().as_ref()));
        hasher.update(self.read_validity.hash());
        hasher.update(self.chain_id);
        hasher.update(self.version.hash());
        hasher.finalize()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        handler: Arc<Box<dyn ChainHandler>>,
        required_read_types: Vec<ReadType>,
    ) -> Result<bool, ReadDataError> {
        // Check if all required read types are present in the read_data.read_type vector
        if !required_read_types.is_empty() {
            let contains_all_required = required_read_types.iter().all(|required_type| {
                self.read_data
                    .read_type
                    .iter()
                    .any(|actual_type| required_type == actual_type)
            });

            if !contains_all_required {
                return Err(ReadDataError::MissingRequiredReadTypes);
            }
        }

        // Check for expiry
        match &self.read_data.read_validity {
            ReadValidity::Block {
                block: expiry_block,
            } => {
                // TODO: there could be an optimisation here to do a multicall that calls
                // is_valid_signature and then calls a function to check signature block_number
                // is less than equal to expiry_block
                let current_block = handler.get_latest_block_number().await?;
                if current_block > *expiry_block {
                    return Err(ReadDataError::SignatureExpired);
                }
            }
            ReadValidity::Timestamp {
                timestamp: expiry_timestamp,
            } => {
                let current_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if current_timestamp > *expiry_timestamp {
                    return Err(ReadDataError::SignatureExpired);
                }
            }
        }

        // Get the verification address from contract address
        let account_address = self.read_data.verifier.signer_address();

        // Verify signature
        let is_valid = handler
            .is_valid_signature(
                (*account_address).into(),
                self.signature
                    .clone()
                    .into_iter()
                    .map(|f| f.into())
                    .collect(),
                self.read_data.hash().into(),
            )
            .await?;

        // If this is an identity, perform additional check
        if is_valid {
            if let ReadVerifier::Identity(identity) = &self.read_data.verifier {
                // Call get_key on the identity to verify it
                let identity_contains_signer = handler
                    .identity_contains_signer(
                        identity.identity_address.into(),
                        (*account_address).into(),
                    )
                    .await?;

                if !identity_contains_signer {
                    return Err(ReadDataError::InvalidIdentityKey);
                }
            }
        }

        Ok(is_valid)
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

    #[test]
    fn test_hash_nonce() {
        let address = Felt::from_hex_unchecked("0x5");

        let read_signature = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: address,
            }),
            vec![ReadType::Nonce {
                nonce: Felt::from_hex_unchecked("0x1"),
            }],
            ReadValidity::Block { block: 100 },
            Felt::from_hex_unchecked("0x3"),
            ReadDataVersion::One,
        );
        assert_eq!(
            read_signature.hash(),
            poseidon_hash_many(vec![
                // read_string
                &Felt::from_hex_unchecked("0x726561645f737472696e67"),
                // contract_address (account hash)
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked(hex::encode("account").as_str()),
                    &address,
                ]),
                // nonce
                &poseidon_hash_many(vec![&poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x6e6f6e6365"),
                    &Felt::from_hex_unchecked("0x1"),
                ]),]),
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
        let address = Felt::from_hex_unchecked("0x5");

        let read_signature = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: address,
            }),
            vec![ReadType::Nonce {
                nonce: Felt::from_hex_unchecked("0x1"),
            }],
            ReadValidity::Timestamp { timestamp: 100 },
            Felt::from_hex_unchecked("0x3"),
            ReadDataVersion::One,
        );
        assert_eq!(
            read_signature.hash(),
            poseidon_hash_many(vec![
                // read_string
                &Felt::from_hex_unchecked("0x726561645f737472696e67"),
                // contract_address (account hash)
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked(hex::encode("account").as_str()),
                    &address,
                ]),
                // nonce
                &poseidon_hash_many(vec![&poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x6e6f6e6365"),
                    &Felt::from(1),
                ]),]),
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
        let address = Felt::from_hex_unchecked("0x5");

        let read_signature = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: address,
            }),
            vec![ReadType::TransactionReceipt {
                transaction_hash: Felt::from_hex_unchecked("0x123"),
            }],
            ReadValidity::Block { block: 100 },
            Felt::from_hex_unchecked("0x356"),
            ReadDataVersion::One,
        );
        assert_eq!(
            read_signature.hash(),
            poseidon_hash_many(vec![
                // read_string
                &Felt::from_hex_unchecked("0x726561645f737472696e67"),
                // contract_address (account hash)
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked(hex::encode("account").as_str()),
                    &address,
                ]),
                // transaction_receipt_events
                &poseidon_hash_many(vec![&poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x7472616e73616374696f6e5f72656365697074"),
                    &Felt::from_hex_unchecked("0x123"),
                ]),]),
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

    #[test]
    fn test_hash_class() {
        let address = Felt::from_hex_unchecked("0x5");

        let read_signature = ReadData::new(
            ReadVerifier::Account(VerifierAccount {
                singer_address: address,
            }),
            vec![ReadType::Class {
                class_hash: Felt::from_hex_unchecked("0x123"),
            }],
            ReadValidity::Block { block: 100 },
            Felt::from_hex_unchecked("0x3"),
            ReadDataVersion::One,
        );
        assert_eq!(
            read_signature.hash(),
            poseidon_hash_many(vec![
                // read_string
                &Felt::from_hex_unchecked("0x726561645f737472696e67"),
                // contract_address (account hash)
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked(hex::encode("account").as_str()),
                    &address,
                ]),
                // class
                &poseidon_hash_many(vec![&poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x636c617373"),
                    &Felt::from_hex_unchecked("0x123"),
                ]),]),
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
    fn test_hash_identity() {
        let account_address = Felt::from_hex_unchecked("0x5");
        let identity_address = Felt::from_hex_unchecked("0x6");

        let read_signature = ReadData::new(
            ReadVerifier::Identity(VerifierIdentity {
                signer_address: account_address,
                identity_address,
            }),
            vec![ReadType::Nonce {
                nonce: Felt::from_hex_unchecked("0x1"),
            }],
            ReadValidity::Block { block: 100 },
            Felt::from_hex_unchecked("0x3"),
            ReadDataVersion::One,
        );

        assert_eq!(
            read_signature.hash(),
            poseidon_hash_many(vec![
                // read_string
                &Felt::from_hex_unchecked("0x726561645f737472696e67"),
                // contract_address (identity hash)
                &poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked(hex::encode("identity").as_str()),
                    &account_address,
                    &identity_address,
                ]),
                // nonce
                &poseidon_hash_many(vec![&poseidon_hash_many(vec![
                    &Felt::from_hex_unchecked("0x6e6f6e6365"),
                    &Felt::from_hex_unchecked("0x1"),
                ]),]),
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
}
