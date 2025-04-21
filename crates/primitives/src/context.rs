use std::sync::Arc;

use crate::{
    rpc::{
        DeclareProgramParams, DeclareTransactionResult, DeployAccountParams, DeployAccountResult,
        GetNonceParams, GetNonceResult, GetProgramParams, GetProgramResult,
        GetTransactionByHashResult, GetTransactionReceiptParams, GetTransactionReceiptResult,
        HexBytes32, SendTransactionParams, SendTransactionResult,
    },
    types::ClassVisibility,
};

// TODO: Divide this into more specific errors
#[derive(Debug, thiserror::Error)]
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
///
/// Note: The current design abstracts the entire method implementation for each chain. However,
/// this is a temporary solution until we integrate more chains. A better design would identify
/// which parts of each method's implementation are chain-specific and which parts are common,
/// allowing us to share code between different chain implementations. We accept this over-abstraction
/// to avoid over-engineering until we have new chains integrating and to bounce back designs with.
#[async_trait::async_trait]
pub trait ChainHandler: Send + Sync {
    /// Declare a new program on the chain and return the transaction hash
    async fn declare_program(
        &self,
        params: DeclareProgramParams,
    ) -> Result<HexBytes32, ChainHandlerError>;

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
    async fn get_program(
        &self,
        class_hash: HexBytes32,
    ) -> Result<GetProgramResult, ChainHandlerError>;

    /// Get the nonce for an account
    async fn get_nonce(&self, address: HexBytes32) -> Result<u32, ChainHandlerError>;

    /// Get a transaction receipt
    async fn get_transaction_receipt(
        &self,
        transaction_hash: HexBytes32,
    ) -> Result<GetTransactionReceiptResult, ChainHandlerError>;

    /// Get the chain ID
    async fn get_chain_id(&self) -> Result<HexBytes32, ChainHandlerError>;

    /// Get latest block number
    async fn get_latest_block_number(&self) -> Result<u64, ChainHandlerError>;

    /// Is valid signature
    async fn is_valid_signature(
        &self,
        account_address: HexBytes32,
        signature: Vec<HexBytes32>,
        message_hash: HexBytes32,
    ) -> Result<bool, ChainHandlerError>;

    /// Identity contains signer
    async fn identity_contains_signer(
        &self,
        identity_address: HexBytes32,
        account_address: HexBytes32,
    ) -> Result<bool, ChainHandlerError>;

    /// Get transaction by hash
    async fn get_transaction_by_hash(
        &self,
        transaction_hash: HexBytes32,
    ) -> Result<GetTransactionByHashResult, ChainHandlerError>;

    /// Contract has function
    async fn contract_has_function(
        &self,
        contract_address: HexBytes32,
        function_name: String,
    ) -> Result<bool, ChainHandlerError>;

    /// Simulate read access check
    async fn simulate_read_access_check(
        &self,
        caller_address: HexBytes32,
        contract_address: HexBytes32,
        function_name: String,
        calldata: Vec<HexBytes32>,
    ) -> Result<bool, ChainHandlerError>;

    /// Compute class hash
    async fn compute_class_hash(
        &self,
        program: &serde_json::Value,
    ) -> Result<HexBytes32, ChainHandlerError>;

    /// Set class visibility
    async fn set_class_visibility(
        &self,
        class_hash: HexBytes32,
        visibility: ClassVisibility,
        sender_address: HexBytes32,
    ) -> Result<HexBytes32, ChainHandlerError>;

    /// Get class visibility
    async fn get_class_visibility(
        &self,
        class_hash: HexBytes32,
    ) -> Result<ClassVisibility, ChainHandlerError>;

    /// Get contract address of declare ACL contract
    fn get_declare_acl_address(&self) -> HexBytes32;
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
