use std::sync::Arc;

use serde::Serialize;
use units_primitives::context::{ChainHandlerError, GlobalContext};
use units_primitives::rpc::{DeclareProgramParams, DeclareTransactionResult};

#[derive(Debug, thiserror::Error, Serialize, PartialEq, Eq)]
pub enum DeclareProgramError {
    #[error("Error setting ACL")]
    ErrorSettingAcl,
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
}

pub async fn declare_program(
    global_ctx: Arc<GlobalContext>,
    params: DeclareProgramParams,
) -> Result<DeclareTransactionResult, DeclareProgramError> {
    let handler = global_ctx.handler();

    // Check if program exists already
    let program_hash = handler.compute_program_hash(&params.program).await?;
    let program_exists = match handler.get_program(program_hash).await {
        Ok(_) => true,
        Err(err) => match err {
            ChainHandlerError::ProgramNotFound(_) => false,
            _ => return Err(DeclareProgramError::ChainHandlerError(err)),
        },
    };

    // Set the ACL before declaring. This is a hacky fix, the idea
    // solution might be to have an indexer sync the chain and set ACLs
    // after we know a declaration has been made OR to add atomicity in Madara
    // for declare and invoke transactions.
    handler
        .set_program_visibility(
            program_hash,
            params.class_visibility,
            params.account_address,
        )
        .await?;

    if program_exists {
        // Don't declare again
        return Ok(DeclareTransactionResult {
            program_hash,
            transaction_hash: None,
            acl_updated: true,
        });
    }

    let declare_transaction_hash = handler.declare_program(params).await?;

    Ok(DeclareTransactionResult {
        program_hash,
        transaction_hash: Some(declare_transaction_hash),
        acl_updated: true,
    })
}
