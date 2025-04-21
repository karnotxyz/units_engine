use crate::{
    units::{errors::UnitsRpcApiError, v0_1_0::api::UnitsReadRpcApiV0_1_0Server},
    RpcContext,
};
use jsonrpsee::core::{async_trait, RpcResult};
use units_primitives::rpc::{
    GetChainIdResult, GetNonceParams, GetNonceResult, GetProgramParams, GetProgramResult,
    GetTransactionReceiptParams, GetTransactionReceiptResult, HexBytes32,
};

#[async_trait]
impl UnitsReadRpcApiV0_1_0Server for RpcContext {
    async fn get_program(&self, get_program: GetProgramParams) -> RpcResult<GetProgramResult> {
        unimplemented!()
    }

    async fn get_nonce(&self, get_nonce: GetNonceParams) -> RpcResult<GetNonceResult> {
        unimplemented!()
    }

    async fn get_transaction_receipt(
        &self,
        get_transaction_receipt: GetTransactionReceiptParams,
    ) -> RpcResult<GetTransactionReceiptResult> {
        unimplemented!()
    }

    async fn get_chain_id(&self) -> RpcResult<GetChainIdResult> {
        let chain_id = units_handlers_common::chain_id::chain_id(self.global_ctx.clone())
            .await
            .map_err(UnitsRpcApiError::from)?;
        Ok(chain_id)
    }
}
