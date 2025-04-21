use std::sync::Arc;

use serde::Serialize;
use units_primitives::{
    context::{ChainHandlerError, GlobalContext},
    read_data::{ReadDataError, ReadType},
    rpc::{Bytes32Error, GetNonceParams, GetNonceResult},
};

const CAN_READ_NONCE_FUNCTION_NAME: &str = "can_read_nonce";

#[derive(Debug, thiserror::Error, Serialize, PartialEq, Eq)]
pub enum NonceError {
    #[error("Read signature not provided")]
    ReadSignatureNotProvided,
    #[error("Empty can get nonce read result")]
    EmptyCanGetNonceReadResult,
    #[error("Nonce read not allowed")]
    NonceReadNotAllowed,
    #[error("Read Data Error: {0}")]
    ReadSignatureError(#[from] ReadDataError),
    #[error("Invalid read signature")]
    InvalidReadSignature,
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
    #[error("Bytes32 error: {0}")]
    Bytes32Error(#[from] Bytes32Error),
}

pub async fn get_nonce(
    global_ctx: Arc<GlobalContext>,
    params: GetNonceParams,
) -> Result<GetNonceResult, NonceError> {
    let handler = global_ctx.handler();

    // Get contract ABI to check for `can_read_nonce` method
    let has_selector = handler
        .contract_has_function(
            params.account_address,
            CAN_READ_NONCE_FUNCTION_NAME.to_string(),
        )
        .await
        .map_err(NonceError::ChainHandlerError)?;

    if has_selector {
        // Check if the read signature is valid by calling `is_valid_signature`
        let signed_read_data = params
            .signed_read_data
            .ok_or(NonceError::ReadSignatureNotProvided)?;

        // Verify the signature and check that it has the required read type
        if !signed_read_data
            .verify(
                handler.clone(),
                vec![ReadType::Nonce {
                    nonce: params.account_address.try_into()?,
                }],
            )
            .await?
        {
            return Err(NonceError::InvalidReadSignature);
        }

        // If the signature is valid, we can now check if the account has access to read the nonce
        // So we build a simulated transaction that tries to call `can_read_nonce` on the smart contract
        // and the "sender_address" is the address of the account that is trying to read the nonce
        // If the account has access, the simulation will succeed and the result will be 0x1 (true)
        let can_read_nonce = handler
            .simulate_read_access_check(
                (*signed_read_data.read_data().read_address()).into(),
                params.account_address,
                CAN_READ_NONCE_FUNCTION_NAME.to_string(),
                vec![],
            )
            .await?;

        if !can_read_nonce {
            return Err(NonceError::NonceReadNotAllowed);
        }
    }

    Ok(GetNonceResult {
        nonce: handler.get_nonce(params.account_address).await?,
    })
}
