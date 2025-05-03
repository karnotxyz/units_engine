use serde_json::json;
use units_handlers_common::{
    call::CallError, declare_program::DeclareProgramError, deploy_account::DeployAccountError,
    get_chain_id::GetChainIdError, get_nonce::GetNonceError, get_program::GetProgramError,
    get_transaction_receipt::GetTransactionReceiptError, send_transaction::SendTransactionError,
};

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(thiserror::Error, Debug)]
pub enum UnitsRpcApiError {
    #[error("Failed to get chain id")]
    GetChainId(#[from] GetChainIdError),
    #[error("Failed to declare program")]
    DeclareProgram(#[from] DeclareProgramError),
    #[error("Failed to send transaction")]
    SendTransaction(#[from] SendTransactionError),
    #[error("Failed to deploy account")]
    DeployAccount(#[from] DeployAccountError),
    #[error("Failed to get program")]
    GetProgram(#[from] GetProgramError),
    #[error("Failed to get nonce")]
    GetNonce(#[from] GetNonceError),
    #[error("Failed to get transaction receipt")]
    GetTransactionReceipt(#[from] GetTransactionReceiptError),
    #[error("Failed to call")]
    Call(#[from] CallError),
}

// TODO: How should we decide the error codes?
impl From<&UnitsRpcApiError> for i32 {
    fn from(err: &UnitsRpcApiError) -> Self {
        match err {
            UnitsRpcApiError::GetChainId(_) => 1,
            UnitsRpcApiError::DeclareProgram(_) => 2,
            UnitsRpcApiError::SendTransaction(_) => 3,
            UnitsRpcApiError::DeployAccount(_) => 4,
            UnitsRpcApiError::GetProgram(_) => 5,
            UnitsRpcApiError::GetNonce(_) => 6,
            UnitsRpcApiError::GetTransactionReceipt(_) => 7,
            UnitsRpcApiError::Call(_) => 8,
        }
    }
}

impl UnitsRpcApiError {
    pub fn data(&self) -> Option<serde_json::Value> {
        match self {
            UnitsRpcApiError::GetChainId(data) => Some(json!(data)),
            UnitsRpcApiError::DeclareProgram(data) => Some(json!(data)),
            UnitsRpcApiError::SendTransaction(data) => Some(json!(data)),
            UnitsRpcApiError::DeployAccount(data) => Some(json!(data)),
            UnitsRpcApiError::GetProgram(data) => Some(json!(data)),
            UnitsRpcApiError::GetNonce(data) => Some(json!(data)),
            UnitsRpcApiError::GetTransactionReceipt(data) => Some(json!(data)),
            UnitsRpcApiError::Call(data) => Some(json!(data)),
        }
    }
}

impl From<UnitsRpcApiError> for jsonrpsee::types::ErrorObjectOwned {
    fn from(err: UnitsRpcApiError) -> Self {
        jsonrpsee::types::ErrorObjectOwned::owned((&err).into(), err.to_string(), err.data())
    }
}
