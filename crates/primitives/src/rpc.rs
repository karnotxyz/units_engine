use crate::{read_data::SignedReadData, types::ClassVisibility};
use serde::{Deserialize, Serialize};
use starknet_crypto::Felt;

//------------------------------------------------------------------------------
// Base Types
//------------------------------------------------------------------------------

/// A 32-byte value encoded as a hex string with 0x prefix
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bytes32([u8; 32]);
#[derive(Debug, thiserror::Error, Serialize, PartialEq, Eq)]
pub enum Bytes32Error {
    #[error("hex string exceeds 32 bytes")]
    TooLong,
    #[error("invalid hex string: {0}")]
    InvalidHex(String),
    #[error("conversion error: {0}")]
    ConversionError(String),
}

impl Bytes32 {
    pub fn from_hex(hex_str: &str) -> Result<Self, Bytes32Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        // If hex string has odd length, prefix with '0' to make it even
        let hex_str = if hex_str.len() % 2 != 0 {
            format!("0{}", hex_str)
        } else {
            hex_str.to_string()
        };
        let bytes = hex::decode(hex_str).map_err(|e| Bytes32Error::InvalidHex(e.to_string()))?;

        if bytes.len() > 32 {
            return Err(Bytes32Error::TooLong);
        }

        let mut array = [0u8; 32];
        array[32 - bytes.len()..].copy_from_slice(&bytes);
        Ok(Self(array))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn to_bytes_be(&self) -> &[u8; 32] {
        &self.0
    }
}

// TODO: move this to Starknet utils or behind a feature flag
impl TryFrom<Bytes32> for Felt {
    type Error = Bytes32Error;

    fn try_from(value: Bytes32) -> Result<Self, Self::Error> {
        // Check if first byte is greater than 0x08 (meaning > 252 bits)
        if value.0[0] > 0x08 {
            return Err(Bytes32Error::ConversionError(
                "value exceeds 2^251 and cannot be converted to Felt".to_string(),
            ));
        }
        Ok(Felt::from_bytes_be(value.to_bytes_be()))
    }
}

impl From<Felt> for Bytes32 {
    fn from(value: Felt) -> Self {
        Bytes32(value.to_bytes_be())
    }
}

/// A 32-byte account address
pub type AccountAddress = Bytes32;

/// A 32-bit unsigned integer used as nonce
pub type Nonce = u32;

/// Event emitted by a contract
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub from_address: Bytes32,
    pub keys: Vec<Bytes32>,
    pub data: Vec<Bytes32>,
}

/// Status of transaction finality
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinalityStatus {
    AcceptedOnUnits,
    AcceptedOnProofStore,
}

/// Status of transaction execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum ExecutionStatus {
    Succeeded,
    Reverted { error: String },
}

//------------------------------------------------------------------------------
// RPC Methods - Parameters and Results
//------------------------------------------------------------------------------

/// Parameters and result for declaring a program
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclareProgramParams {
    pub account_address: AccountAddress,
    pub signature: Vec<Bytes32>,
    pub nonce: Nonce,
    pub program: serde_json::Value,
    pub compiled_program_hash: Option<Bytes32>,
    pub class_visibility: ClassVisibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclareTransactionResult {
    pub transaction_hash: Option<Bytes32>,
    pub class_hash: Bytes32,
    pub acl_updated: bool,
}

/// Parameters and result for deploying an account
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployAccountParams {
    pub signature: Vec<Bytes32>,
    pub nonce: Nonce,
    pub constructor_calldata: Vec<Bytes32>,
    pub program_hash: Bytes32,
    pub account_address_salt: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployAccountResult {
    pub transaction_hash: Bytes32,
    pub account_address: Bytes32,
}

/// Parameters and result for sending a transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendTransactionParams {
    pub account_address: AccountAddress,
    pub signature: Vec<Bytes32>,
    pub nonce: Nonce,
    pub calldata: Vec<Bytes32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendTransactionResult {
    pub transaction_hash: Bytes32,
}

/// Parameters and result for getting a nonce
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetNonceParams {
    pub account_address: AccountAddress,
    pub signed_read_data: Option<SignedReadData>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetNonceResult {
    pub nonce: u32,
}

/// Parameters and result for getting a transaction receipt
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTransactionReceiptParams {
    pub transaction_hash: Bytes32,
    pub signed_read_data: SignedReadData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTransactionReceiptResult {
    pub transaction_hash: Bytes32,
    pub events: Vec<Event>,
    pub finality_status: FinalityStatus,
    pub execution_status: ExecutionStatus,
}

/// Parameters and result for getting a class
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetProgramParams {
    pub class_hash: Bytes32,
    pub signed_read_data: Option<SignedReadData>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetProgramResult {
    pub program: serde_json::Value,
}

/// Result for getting chain ID (no parameters required)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetChainIdResult {
    pub chain_id: Bytes32,
}

/// Result for getting a transaction by hash
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTransactionByHashResult {
    pub sender_address: Bytes32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("0x0", vec![0; 32])]
    #[case("0", vec![0; 32])]
    #[case("0x01", {
        let mut bytes = vec![0; 31];
        bytes.push(1);
        bytes
    })]
    #[case("0x0000000000000000000000000000000000000000000000000000000000000001", {
        let mut bytes = vec![0; 31];
        bytes.push(1);
        bytes
    })]
    #[case("0xdeadbeef", {
        let mut bytes = vec![0; 28];
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        bytes
    })]
    fn test_bytes32_from_hex_valid(#[case] input: &str, #[case] expected: Vec<u8>) {
        let result = Bytes32::from_hex(input).unwrap();
        assert_eq!(result.0.to_vec(), expected);
    }

    #[rstest]
    #[case("0xzz", Bytes32Error::InvalidHex("invalid character 'z' at position 2".to_string()))]
    #[case(
        "0x000000000000000000000000000000000000000000000000000000000000000001",
        Bytes32Error::TooLong
    )]
    #[case("0xgh", Bytes32Error::InvalidHex("invalid character 'g' at position 2".to_string()))]
    fn test_bytes32_from_hex_invalid(#[case] input: &str, #[case] expected_error: Bytes32Error) {
        match Bytes32::from_hex(input) {
            Err(error) => match (error, expected_error) {
                (Bytes32Error::TooLong, Bytes32Error::TooLong) => (),
                (Bytes32Error::InvalidHex(e1), Bytes32Error::InvalidHex(e2)) => {
                    assert_eq!(format!("{:?}", e1), format!("{:?}", e2))
                }
                _ => panic!("Unexpected error"),
            },
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    #[rstest]
    #[case([0u8; 32], "0000000000000000000000000000000000000000000000000000000000000000")]
    #[case({
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        bytes
    }, "0000000000000000000000000000000000000000000000000000000000000001")]
    #[case({
        let mut bytes = [0u8; 32];
        bytes[28..].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        bytes
    }, "00000000000000000000000000000000000000000000000000000000deadbeef")]
    fn test_bytes32_to_hex(#[case] input: [u8; 32], #[case] expected: &str) {
        let bytes = Bytes32(input);
        assert_eq!(bytes.to_hex(), expected);
    }

    #[test]
    fn test_bytes32_to_bytes_be() {
        let bytes = [42u8; 32];
        let bytes32 = Bytes32(bytes);
        assert_eq!(bytes32.to_bytes_be(), &bytes);
    }

    #[rstest]
    #[case("0x0")]
    #[case("0xdeadbeef")]
    #[case("0x0000000000000000000000000000000000000000000000000000000000000001")]
    fn test_bytes32_roundtrip(#[case] input: &str) {
        let bytes = Bytes32::from_hex(input).unwrap();
        let hex_str = bytes.to_hex();

        // Remove leading zeros and compare
        let normalized_input = input.strip_prefix("0x").unwrap_or(input);
        let normalized_input = normalized_input.trim_start_matches('0');
        let normalized_output = hex_str.trim_start_matches('0');
        assert_eq!(normalized_input, normalized_output);
    }

    #[rstest]
    #[case("0x0")]
    #[case("0x1234567890abcdef")]
    #[case("0x800000000000000000000000000000000000000000000000000000000000000")] // Max valid Felt (252 bits set)
    fn test_bytes32_to_felt_valid(#[case] input: &str) {
        let bytes = Bytes32::from_hex(input).unwrap();
        let result = Felt::try_from(bytes);
        assert!(result.is_ok());
    }

    #[rstest]
    #[case("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")] // All bits set
    #[case("0x8000000000000000000000000000000000000000000000000000000000000000")] // MSB set
    #[case("0xf000000000000000000000000000000000000000000000000000000000000000")] // Top 4 bits set
    fn test_bytes32_to_felt_invalid(#[case] input: &str) {
        let bytes = Bytes32::from_hex(input).unwrap();
        let result = Felt::try_from(bytes);
        assert_matches::assert_matches!(result, Err(Bytes32Error::ConversionError(_)));
    }

    #[rstest]
    #[case("0x0")]
    #[case("0x1234567890abcdef")]
    #[case("0x800000000000000000000000000000000000000000000000000000000000000")]
    fn test_bytes32_to_felt_roundtrip(#[case] input: &str) {
        let bytes = Bytes32::from_hex(input).unwrap();
        let felt = Felt::try_from(bytes).unwrap();
        println!("felt: {:?}", felt);
        println!("felt max: {:?}", Felt::ELEMENT_UPPER_BOUND);
        let bytes_from_felt: Bytes32 = Bytes32::from(felt);

        assert_eq!(bytes_from_felt, bytes);
    }
}
