use crate::{
    units::{errors::UnitsRpcApiError, v0_1_0::api::UnitsReadRpcApiV0_1_0Server},
    RpcContext,
};
use jsonrpsee::core::{async_trait, RpcResult};
use units_primitives::rpc::{
    GetChainIdResult, GetNonceParams, GetNonceResult, GetProgramParams, GetProgramResult,
    GetTransactionReceiptParams, GetTransactionReceiptResult,
};

#[async_trait]
impl UnitsReadRpcApiV0_1_0Server for RpcContext {
    async fn get_program(&self, get_program: GetProgramParams) -> RpcResult<GetProgramResult> {
        let result =
            units_handlers_common::get_program::get_program(self.global_ctx.clone(), get_program)
                .await
                .map_err(UnitsRpcApiError::from)?;
        Ok(result)
    }

    async fn get_nonce(&self, get_nonce: GetNonceParams) -> RpcResult<GetNonceResult> {
        let result =
            units_handlers_common::get_nonce::get_nonce(self.global_ctx.clone(), get_nonce)
                .await
                .map_err(UnitsRpcApiError::from)?;
        Ok(result)
    }

    async fn get_transaction_receipt(
        &self,
        get_transaction_receipt: GetTransactionReceiptParams,
    ) -> RpcResult<GetTransactionReceiptResult> {
        let result = units_handlers_common::get_transaction_receipt::get_transaction_receipt(
            self.global_ctx.clone(),
            get_transaction_receipt,
        )
        .await
        .map_err(UnitsRpcApiError::from)?;
        Ok(result)
    }

    async fn get_chain_id(&self) -> RpcResult<GetChainIdResult> {
        let chain_id = units_handlers_common::get_chain_id::get_chain_id(self.global_ctx.clone())
            .await
            .map_err(UnitsRpcApiError::from)?;
        Ok(chain_id)
    }
}
