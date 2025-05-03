use std::sync::Arc;

use serde::Serialize;
use units_primitives::{
    context::{ChainHandlerError, GlobalContext},
    read_data::{ReadDataError, ReadType},
    rpc::{Bytes32Error, CallParams, CallResult, FeltVec},
};

#[derive(Debug, thiserror::Error, Serialize, PartialEq, Eq)]
pub enum CallError {
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
    #[error("Invalid read signature")]
    InvalidReadSignature,
    #[error("Bytes32 error: {0}")]
    Bytes32Error(#[from] Bytes32Error),
    #[error("Read data error: {0}")]
    ReadDataError(#[from] ReadDataError),
}

pub async fn call(
    global_ctx: Arc<GlobalContext>,
    params: CallParams,
) -> Result<CallResult, CallError> {
    let handler = global_ctx.handler();

    // Verify the signature and check that it has the required read type
    if !params
        .signed_read_data
        .verify(
            handler.clone(),
            vec![ReadType::Call {
                contract_address: params.contract_address.try_into()?,
                function_selector: params.function_selector.try_into()?,
                calldata: FeltVec::try_from(params.calldata.clone())?.0,
            }],
        )
        .await?
    {
        return Err(CallError::InvalidReadSignature);
    }

    // Call the contract
    let result = handler
        .call(
            params.contract_address,
            params.function_selector,
            params.calldata,
        )
        .await?;

    Ok(CallResult { result })
}
