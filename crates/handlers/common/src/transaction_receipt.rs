use std::sync::Arc;

use serde::Serialize;
use units_primitives::{
    context::{ChainHandlerError, GlobalContext},
    read_data::ReadDataError,
    rpc::{Bytes32Error, GetTransactionReceiptParams, GetTransactionReceiptResult},
};

#[derive(Debug, thiserror::Error, Serialize, PartialEq, Eq)]
pub enum TransactionReceiptError {
    #[error("More events than expected")]
    MoreEventsThanExpected,
    #[error("Invalid read signature")]
    InvalidReadSignature,
    #[error("Read Data Error: {0}")]
    ReadSignatureError(#[from] ReadDataError),
    #[error("Invalid transaction type")]
    InvalidTransactionType,
    #[error("Invalid sender address")]
    InvalidSenderAddress,
    #[error("Chain handler error: {0}")]
    ChainHandlerError(#[from] ChainHandlerError),
    #[error("Bytes32 error: {0}")]
    Bytes32Error(#[from] Bytes32Error),
}

const CAN_READ_EVENT_FUNCTION_NAME: &str = "can_read_event";

pub async fn get_transaction_receipt(
    global_ctx: Arc<GlobalContext>,
    params: GetTransactionReceiptParams,
) -> Result<GetTransactionReceiptResult, TransactionReceiptError> {
    let handler = global_ctx.handler();

    // Verify signature and ensure it has the required read type
    if !params
        .signed_read_data
        .verify(
            handler.clone(),
            vec![units_primitives::read_data::ReadType::TransactionReceipt {
                transaction_hash: params.transaction_hash.try_into()?,
            }],
        )
        .await?
    {
        return Err(TransactionReceiptError::InvalidReadSignature);
    }

    // Check if reader is the transaction originator
    let raw_txn = handler
        .get_transaction_by_hash(params.transaction_hash)
        .await?;
    let sender_address = raw_txn.sender_address;
    if sender_address != (*params.signed_read_data.read_data().read_address()).into() {
        return Err(TransactionReceiptError::InvalidSenderAddress);
    }

    // Get the receipt
    let mut receipt = handler
        .get_transaction_receipt(params.transaction_hash)
        .await?;

    if receipt.events.is_empty() {
        // If there are no events, we can return the receipt as is
        return Ok(receipt);
    }

    // Fetch events and the contract address from where the event was emitted
    // This is done because we need to call the contract address with the CAN_READ_EVENT_SELECTOR
    // to check if the user has access to read the events
    let mut events = receipt.events;

    let mut can_read_events = Vec::new();
    for event in events.iter() {
        let has_selector = handler
            .contract_has_function(event.from_address, CAN_READ_EVENT_FUNCTION_NAME.to_string())
            .await?;

        let can_read = if has_selector {
            handler
                .simulate_read_access_check(
                    (*params.signed_read_data.read_data().read_address()).into(),
                    event.from_address,
                    CAN_READ_EVENT_FUNCTION_NAME.to_string(),
                    vec![event.keys[0]],
                )
                .await
                .map_err(TransactionReceiptError::ChainHandlerError)?
        } else {
            true
        };
        can_read_events.push(can_read);
    }

    // Filter events based on read permissions
    events = events
        .into_iter()
        .zip(can_read_events)
        .filter_map(|(event, can_read)| if can_read { Some(event) } else { None })
        .collect();

    receipt.events = events;

    Ok(receipt)
}
