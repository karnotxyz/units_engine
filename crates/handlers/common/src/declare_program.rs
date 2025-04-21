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

    // Check if class exists already
    let class_hash = handler.compute_class_hash(&params.program).await?;
    let class_exists = match handler.get_program(class_hash).await {
        Ok(_) => true,
        Err(err) => match err {
            ChainHandlerError::ProgramNotFound(_) => false,
            _ => return Err(DeclareProgramError::ChainHandlerError(err)),
        },
    };

    if class_exists {
        // Set the ACL before declaring. This is a hacky fix, the ideal
        // solution might be to have an indexer sync the chain and set ACLs
        // after we know a declaration has been made OR to add atomicity in Madara
        // for declare and invoke transactions.
        handler
            .set_class_visibility(class_hash, params.class_visibility, params.account_address)
            .await?;

        return Ok(DeclareTransactionResult {
            class_hash,
            transaction_hash: None,
            acl_updated: true,
        });
    }

    let declare_transaction_hash = handler.declare_program(params).await?;

    Ok(DeclareTransactionResult {
        class_hash,
        transaction_hash: Some(declare_transaction_hash),
        acl_updated: true,
    })
}
