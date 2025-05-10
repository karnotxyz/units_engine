use std::sync::Arc;

use serde::Serialize;

use crate::{
    rpc::{
        Bytes32, DeclareProgramParams, DeployAccountParams, DeployAccountResult, GetProgramResult,
        GetTransactionByHashResult, GetTransactionReceiptResult, SendTransactionParams,
        SendTransactionResult,
    },
    types::ClassVisibility,
};

// TODO: Divide this into more specific errors
#[derive(Debug, thiserror::Error, Serialize, PartialEq, Eq)]
pub enum ChainHandlerError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Provider error: {0}")]
    ProviderError(String),
    #[error("Invalid return type for function call: {0}")]
    InvalidReturnTypeForFunctionCall(String),
    #[error("Invalid transaction type")]
    InvalidTransactionType,
    #[error("Invalid function name: {0}")]
    InvalidFunctionName(String),
    #[error("Simulation error: {0}")]
    SimulationError(String),
    #[error("Simulation reverted: {0}")]
    SimulationReverted(String),
    #[error("Conversion error: {0}")]
    ConversionError(String),
    #[error("Invalid program: {0}")]
    InvalidProgram(String),
    #[error("Class not found: {0}")]
    ProgramNotFound(String),
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),
}

/// The ChainHandler trait defines the interface for handling blockchain operations in UNITS.
///
/// This trait is designed to allow easy integration of new blockchain stacks into the UNITS ecosystem.
/// Each chain implementation must provide these core functionalities to be compatible with UNITS.
#[async_trait::async_trait]
pub trait ChainHandler: Send + Sync {
    /// Declare a new program on the chain and return the transaction hash
    async fn declare_program(
        &self,
        params: DeclareProgramParams,
    ) -> Result<Bytes32, ChainHandlerError>;

    /// Send a transaction to the chain
    async fn send_transaction(
        &self,
        params: SendTransactionParams,
    ) -> Result<SendTransactionResult, ChainHandlerError>;

    /// Deploy a new account on the chain
    async fn deploy_account(
        &self,
        params: DeployAccountParams,
    ) -> Result<DeployAccountResult, ChainHandlerError>;

    /// Get a program by its hash
    async fn get_program(&self, class_hash: Bytes32)
        -> Result<GetProgramResult, ChainHandlerError>;

    /// Get the nonce for an account
    async fn get_nonce(&self, address: Bytes32) -> Result<u32, ChainHandlerError>;

    /// Get a transaction receipt
    async fn get_transaction_receipt(
        &self,
        transaction_hash: Bytes32,
    ) -> Result<GetTransactionReceiptResult, ChainHandlerError>;

    /// Get the chain ID
    async fn get_chain_id(&self) -> Result<Bytes32, ChainHandlerError>;

    /// Get latest block number
    async fn get_latest_block_number(&self) -> Result<u64, ChainHandlerError>;

    /// Is valid signature
    async fn is_valid_signature(
        &self,
        account_address: Bytes32,
        signature: Vec<Bytes32>,
        message_hash: Bytes32,
    ) -> Result<bool, ChainHandlerError>;

    /// Identity contains signer
    async fn identity_contains_signer(
        &self,
        identity_address: Bytes32,
        account_address: Bytes32,
    ) -> Result<bool, ChainHandlerError>;

    /// Get transaction by hash
    async fn get_transaction_by_hash(
        &self,
        transaction_hash: Bytes32,
    ) -> Result<GetTransactionByHashResult, ChainHandlerError>;

    /// Contract has function
    async fn contract_has_function(
        &self,
        contract_address: Bytes32,
        function_name: String,
    ) -> Result<bool, ChainHandlerError>;

    /// Simulate call
    async fn simulate_call(
        &self,
        caller_address: Bytes32,
        contract_address: Bytes32,
        function_name: String,
        calldata: Vec<Bytes32>,
    ) -> Result<Vec<Bytes32>, ChainHandlerError>;

    /// Compute class hash
    async fn compute_program_hash(
        &self,
        program: &serde_json::Value,
    ) -> Result<Bytes32, ChainHandlerError>;

    /// Set class visibility
    async fn set_program_visibility(
        &self,
        class_hash: Bytes32,
        visibility: ClassVisibility,
        sender_address: Bytes32,
    ) -> Result<Bytes32, ChainHandlerError>;

    /// Get class visibility
    async fn get_program_visibility(
        &self,
        class_hash: Bytes32,
    ) -> Result<ClassVisibility, ChainHandlerError>;

    /// Call a contract
    async fn call(
        &self,
        contract_address: Bytes32,
        function_name: Bytes32,
        calldata: Vec<Bytes32>,
    ) -> Result<Vec<Bytes32>, ChainHandlerError>;

    /// Get contract address of declare ACL contract
    fn get_declare_acl_address(&self) -> Bytes32;

    /// Simulate read access check
    async fn simulate_read_access_check(
        &self,
        caller_address: Bytes32,
        contract_address: Bytes32,
        function_name: String,
        calldata: Vec<Bytes32>,
    ) -> Result<bool, ChainHandlerError> {
        match self.simulate_call(caller_address, contract_address, function_name, calldata).await {
            Ok(result) => {
                let can_read = result
                    .get(2)
                    .ok_or(ChainHandlerError::SimulationError(
                        "Invalid result for boolean read".to_string(),
                    ))?;
                if can_read != &Bytes32::from_hex("0x1").unwrap() {
                    return Ok(false);
                }
                Ok(true)
            }
            Err(ChainHandlerError::SimulationReverted(_)) => {
                return Ok(false);
            }
            Err(e) => Err(e),
        }
    }
}

pub struct GlobalContext {
    handler: Arc<Box<dyn ChainHandler>>,
}

impl GlobalContext {
    pub fn new(handler: Arc<Box<dyn ChainHandler>>) -> Self {
        Self { handler }
    }

    pub fn handler(&self) -> Arc<Box<dyn ChainHandler>> {
        self.handler.clone()
    }
}
