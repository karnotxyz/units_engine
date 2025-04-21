use serde_json::json;
use units_handlers_common::{
    chain_id::ChainIdError, declare_program::DeclareProgramError, deploy_account::DeployAccountError, get_program::GetProgramError, nonce::NonceError, send_transaction::SendTransactionError, transaction_receipt::TransactionReceiptError
};

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(thiserror::Error, Debug)]
pub enum UnitsRpcApiError {
    #[error("Failed to get chain id")]
    FailedToGetChainId(#[from] ChainIdError),
    #[error("Failed to declare program")]
    FailedToDeclareProgram(#[from] DeclareProgramError),
    #[error("Failed to send transaction")]
    FailedToSendTransaction(#[from] SendTransactionError),
    #[error("Failed to deploy account")]
    FailedToDeployAccount(#[from] DeployAccountError),
    #[error("Failed to get program")]
    FailedToGetProgram(#[from] GetProgramError),
    #[error("Failed to get nonce")]
    FailedToGetNonce(#[from] NonceError),
    #[error("Failed to get transaction receipt")]
    FailedToGetTransactionReceipt(#[from] TransactionReceiptError),
}

// TODO: How should we decide the error codes?
impl From<&UnitsRpcApiError> for i32 {
    fn from(err: &UnitsRpcApiError) -> Self {
        match err {
            UnitsRpcApiError::FailedToGetChainId(_) => 1,
            UnitsRpcApiError::FailedToDeclareProgram(_) => 2,
            UnitsRpcApiError::FailedToSendTransaction(_) => 3,
            UnitsRpcApiError::FailedToDeployAccount(_) => 4,
            UnitsRpcApiError::FailedToGetProgram(_) => 5,
            UnitsRpcApiError::FailedToGetNonce(_) => 6,
            UnitsRpcApiError::FailedToGetTransactionReceipt(_) => 7,
        }
    }
}

impl UnitsRpcApiError {
    pub fn data(&self) -> Option<serde_json::Value> {
        match self {
            UnitsRpcApiError::FailedToGetChainId(data) => Some(json!(data)),
            UnitsRpcApiError::FailedToDeclareProgram(data) => Some(json!(data)),
            UnitsRpcApiError::FailedToSendTransaction(data) => Some(json!(data)),
            UnitsRpcApiError::FailedToDeployAccount(data) => Some(json!(data)),
            UnitsRpcApiError::FailedToGetProgram(data) => Some(json!(data)),
            UnitsRpcApiError::FailedToGetNonce(data) => Some(json!(data)),
            UnitsRpcApiError::FailedToGetTransactionReceipt(data) => Some(json!(data)),
        }
    }
}

impl From<UnitsRpcApiError> for jsonrpsee::types::ErrorObjectOwned {
    fn from(err: UnitsRpcApiError) -> Self {
        jsonrpsee::types::ErrorObjectOwned::owned((&err).into(), err.to_string(), err.data())
    }
}
