use std::sync::Arc;

use serde::Serialize;
use units_primitives::context::{ChainHandlerError, GlobalContext};
use units_primitives::read_data::{ReadDataError, ReadType};
use units_primitives::rpc::{Bytes32Error, GetProgramParams, GetProgramResult};
use units_primitives::types::{ClassVisibility, ClassVisibilityError};

pub const HAS_READ_ACCESS_FUNCTION_NAME: &str = "has_read_access";

#[derive(Debug, thiserror::Error, Serialize, PartialEq, Eq)]
pub enum GetProgramError {
    #[error("Read signature not provided")]
    ReadSignatureNotProvided,
    #[error("Class read not allowed")]
    ClassReadNotAllowed,
    #[error("Invalid class visibility")]
    InvalidClassVisibility(#[from] ClassVisibilityError),
    #[error("Read data error: {0}")]
    ReadDataError(#[from] ReadDataError),
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
    #[error("Bytes32 error: {0}")]
    Bytes32Error(#[from] Bytes32Error),
}

pub async fn get_program(
    global_ctx: Arc<GlobalContext>,
    params: GetProgramParams,
) -> Result<GetProgramResult, GetProgramError> {
    let handler = global_ctx.handler();

    // Check if the contract is public
    let visibility: ClassVisibility = handler.get_class_visibility(params.class_hash).await?;

    if visibility != ClassVisibility::Public {
        // Check if user has access to the contract
        let signed_read_data = params
            .signed_read_data
            .ok_or(GetProgramError::ReadSignatureNotProvided)?;

        // Verify the signature and check that it has the required read type
        if !signed_read_data
            .verify(
                handler.clone(),
                vec![ReadType::Class {
                    class_hash: params.class_hash.try_into()?,
                }],
            )
            .await
            .map_err(GetProgramError::ReadDataError)?
        {
            return Err(GetProgramError::ClassReadNotAllowed);
        }

        let has_read_access = handler
            .simulate_read_access_check(
                (*signed_read_data.read_data().read_address()).into(),
                handler.get_declare_acl_address(),
                HAS_READ_ACCESS_FUNCTION_NAME.to_string(),
                vec![params.class_hash],
            )
            .await?;

        if !has_read_access {
            return Err(GetProgramError::ClassReadNotAllowed);
        }
    }

    let class = handler.get_program(params.class_hash).await?;
    Ok(class)
}
