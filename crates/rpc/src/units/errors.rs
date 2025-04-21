use serde_json::json;
use units_handlers_common::chain_id::ChainIdError;

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(thiserror::Error, Debug)]
pub enum UnitsRpcApiError {
    #[error("Failed to get chain id")]
    FailedToGetChainId(#[from] ChainIdError),
}

// TODO: How should we decide the error codes?
impl From<&UnitsRpcApiError> for i32 {
    fn from(err: &UnitsRpcApiError) -> Self {
        match err {
            UnitsRpcApiError::FailedToGetChainId(_) => 1,
        }
    }
}

impl UnitsRpcApiError {
    pub fn data(&self) -> Option<serde_json::Value> {
        match self {
            UnitsRpcApiError::FailedToGetChainId(data) => Some(json!(data)),
            _ => None,
        }
    }
}

impl From<UnitsRpcApiError> for jsonrpsee::types::ErrorObjectOwned {
    fn from(err: UnitsRpcApiError) -> Self {
        jsonrpsee::types::ErrorObjectOwned::owned((&err).into(), err.to_string(), err.data())
    }
}
