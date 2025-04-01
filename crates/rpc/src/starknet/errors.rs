use jsonrpsee::core::Cow;
use serde_json::json;
use starknet::providers::ProviderError;

// Comes from the RPC Spec:
// https://github.com/starkware-libs/starknet-specs/blob/0e859ff905795f789f1dfd6f7340cdaf5015acc8/api/starknet_write_api.json#L227
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(thiserror::Error, Debug)]
pub enum StarknetRpcApiError {
    #[error("Failed to write transaction")]
    FailedToReceiveTxn { err: Option<Cow<'static, str>> },
    #[error("Contract not found")]
    ContractNotFound,
    #[error("Block not found")]
    BlockNotFound,
    #[error("Invalid transaction hash")]
    InvalidTxnHash,
    #[error("Invalid tblock hash")]
    InvalidBlockHash,
    #[error("Invalid transaction index in a block")]
    InvalidTxnIndex,
    #[error("Class hash not found")]
    ClassHashNotFound,
    #[error("Transaction hash not found")]
    TxnHashNotFound,
    #[error("Requested page size is too big")]
    PageSizeTooBig,
    #[error("There are no blocks")]
    NoBlocks,
    #[error("The supplied continuation token is invalid or unknown")]
    InvalidContinuationToken,
    #[error("Too many keys provided in a filter")]
    TooManyKeysInFilter,
    #[error("Failed to fetch pending transactions")]
    FailedToFetchPendingTransactions,
    #[error("Contract error")]
    ContractError,
    #[error("Transaction execution error")]
    TxnExecutionError { tx_index: usize, error: String },
    #[error("Invalid contract class")]
    InvalidContractClass,
    #[error("Class already declared")]
    ClassAlreadyDeclared,
    #[error("Invalid transaction nonce")]
    InvalidTxnNonce,
    #[error("Max fee is smaller than the minimal transaction cost (validation plus fee transfer)")]
    InsufficientMaxFee,
    #[error("Account balance is smaller than the transaction's max_fee")]
    InsufficientAccountBalance,
    #[error("Account validation failed")]
    ValidationFailure { error: Cow<'static, str> },
    #[error("Compilation failed")]
    CompilationFailed,
    #[error("Contract class size is too large")]
    ContractClassSizeTooLarge,
    #[error("Sender address is not an account contract")]
    NonAccount,
    #[error("A transaction with the same hash already exists in the mempool")]
    DuplicateTxn,
    #[error("The compiled class hash did not match the one supplied in the transaction")]
    CompiledClassHashMismatch,
    #[error("The transaction version is not supported")]
    UnsupportedTxnVersion,
    #[error("The contract class version is not supported")]
    UnsupportedContractClassVersion,
    #[error("An unexpected error occurred")]
    ErrUnexpectedError { data: String },
    #[error("Internal server error")]
    InternalServerError,
    #[error("Unimplemented method")]
    UnimplementedMethod,
}

impl From<&StarknetRpcApiError> for i32 {
    fn from(err: &StarknetRpcApiError) -> Self {
        match err {
            StarknetRpcApiError::FailedToReceiveTxn { .. } => 1,
            StarknetRpcApiError::ContractNotFound => 20,
            StarknetRpcApiError::BlockNotFound => 24,
            StarknetRpcApiError::InvalidTxnHash => 25,
            StarknetRpcApiError::InvalidBlockHash => 26,
            StarknetRpcApiError::InvalidTxnIndex => 27,
            StarknetRpcApiError::ClassHashNotFound => 28,
            StarknetRpcApiError::TxnHashNotFound => 29,
            StarknetRpcApiError::PageSizeTooBig => 31,
            StarknetRpcApiError::NoBlocks => 32,
            StarknetRpcApiError::InvalidContinuationToken => 33,
            StarknetRpcApiError::TooManyKeysInFilter => 34,
            StarknetRpcApiError::FailedToFetchPendingTransactions => 38,
            StarknetRpcApiError::ContractError => 40,
            StarknetRpcApiError::TxnExecutionError { .. } => 41,
            StarknetRpcApiError::InvalidContractClass => 50,
            StarknetRpcApiError::ClassAlreadyDeclared => 51,
            StarknetRpcApiError::InvalidTxnNonce => 52,
            StarknetRpcApiError::InsufficientMaxFee => 53,
            StarknetRpcApiError::InsufficientAccountBalance => 54,
            StarknetRpcApiError::ValidationFailure { .. } => 55,
            StarknetRpcApiError::CompilationFailed => 56,
            StarknetRpcApiError::ContractClassSizeTooLarge => 57,
            StarknetRpcApiError::NonAccount => 58,
            StarknetRpcApiError::DuplicateTxn => 59,
            StarknetRpcApiError::CompiledClassHashMismatch => 60,
            StarknetRpcApiError::UnsupportedTxnVersion => 61,
            StarknetRpcApiError::UnsupportedContractClassVersion => 62,
            StarknetRpcApiError::ErrUnexpectedError { .. } => 63,
            StarknetRpcApiError::InternalServerError => 500,
            StarknetRpcApiError::UnimplementedMethod => 501,
        }
    }
}

impl StarknetRpcApiError {
    pub fn data(&self) -> Option<serde_json::Value> {
        match self {
            StarknetRpcApiError::ErrUnexpectedError { data } => Some(json!(data)),
            StarknetRpcApiError::ValidationFailure { error } => Some(json!(error)),
            StarknetRpcApiError::FailedToReceiveTxn { err } => err.as_ref().map(|err| json!(err)),
            StarknetRpcApiError::TxnExecutionError { tx_index, error } => Some(json!({
                "transaction_index": tx_index,
                "execution_error": error,
            })),
            _ => None,
        }
    }
}

impl From<StarknetRpcApiError> for jsonrpsee::types::ErrorObjectOwned {
    fn from(err: StarknetRpcApiError) -> Self {
        jsonrpsee::types::ErrorObjectOwned::owned((&err).into(), err.to_string(), err.data())
    }
}

impl From<ProviderError> for StarknetRpcApiError {
    fn from(err: ProviderError) -> Self {
        use starknet::core::types::StarknetError;

        match err {
            ProviderError::StarknetError(starknet_err) => match starknet_err {
                StarknetError::TransactionHashNotFound => StarknetRpcApiError::TxnHashNotFound,
                StarknetError::ContractNotFound => StarknetRpcApiError::ContractNotFound,
                StarknetError::BlockNotFound => StarknetRpcApiError::BlockNotFound,
                StarknetError::ClassHashNotFound => StarknetRpcApiError::ClassHashNotFound,
                StarknetError::InvalidTransactionNonce => StarknetRpcApiError::InvalidTxnNonce,
                StarknetError::InsufficientMaxFee => StarknetRpcApiError::InsufficientMaxFee,
                StarknetError::InsufficientAccountBalance => {
                    StarknetRpcApiError::InsufficientAccountBalance
                }
                StarknetError::ValidationFailure(err) => {
                    StarknetRpcApiError::ValidationFailure { error: err.into() }
                }
                StarknetError::CompilationFailed => StarknetRpcApiError::CompilationFailed,
                StarknetError::NonAccount => StarknetRpcApiError::NonAccount,
                StarknetError::CompiledClassHashMismatch => {
                    StarknetRpcApiError::CompiledClassHashMismatch
                }
                StarknetError::UnsupportedContractClassVersion => {
                    StarknetRpcApiError::UnsupportedContractClassVersion
                }
                StarknetError::UnexpectedError(err) => {
                    StarknetRpcApiError::ErrUnexpectedError { data: err }
                }
                StarknetError::FailedToReceiveTransaction => {
                    StarknetRpcApiError::FailedToReceiveTxn { err: None }
                }
                StarknetError::InvalidTransactionIndex => StarknetRpcApiError::InvalidTxnIndex,
                StarknetError::PageSizeTooBig => StarknetRpcApiError::PageSizeTooBig,
                StarknetError::NoBlocks => StarknetRpcApiError::NoBlocks,
                StarknetError::InvalidContinuationToken => {
                    StarknetRpcApiError::InvalidContinuationToken
                }
                StarknetError::TooManyKeysInFilter => StarknetRpcApiError::TooManyKeysInFilter,
                StarknetError::ContractError(_) => StarknetRpcApiError::ContractError,
                StarknetError::TransactionExecutionError(err) => {
                    StarknetRpcApiError::TxnExecutionError {
                        tx_index: err.transaction_index as usize,
                        error: err.execution_error,
                    }
                }
                StarknetError::DuplicateTx => StarknetRpcApiError::DuplicateTxn,
                StarknetError::UnsupportedTxVersion => StarknetRpcApiError::UnsupportedTxnVersion,
                StarknetError::ClassAlreadyDeclared => StarknetRpcApiError::ClassAlreadyDeclared,
                StarknetError::ContractClassSizeIsTooLarge => {
                    StarknetRpcApiError::ContractClassSizeTooLarge
                }
                StarknetError::NoTraceAvailable(_) => StarknetRpcApiError::InternalServerError,
            },
            ProviderError::RateLimited => StarknetRpcApiError::ErrUnexpectedError {
                data: "Rate limited".to_string(),
            },
            ProviderError::ArrayLengthMismatch => StarknetRpcApiError::ErrUnexpectedError {
                data: "Array length mismatch".to_string(),
            },
            ProviderError::Other(err) => StarknetRpcApiError::ErrUnexpectedError {
                data: err.to_string(),
            },
        }
    }
}
