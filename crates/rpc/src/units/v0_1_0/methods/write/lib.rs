use crate::{
    units::{errors::UnitsRpcApiError, v0_1_0::api::UnitsWriteRpcApiV0_1_0Server},
    RpcContext,
};
use jsonrpsee::core::{async_trait, RpcResult};
use units_primitives::rpc::{
    DeclareProgramParams, DeclareTransactionResult, DeployAccountParams, DeployAccountResult,
    SendTransactionParams, SendTransactionResult,
};

#[async_trait]
impl UnitsWriteRpcApiV0_1_0Server for RpcContext {
    async fn declare_program(
        &self,
        declare_program: DeclareProgramParams,
    ) -> RpcResult<DeclareTransactionResult> {
        let result = units_handlers_common::declare_program::declare_program(
            self.global_ctx.clone(),
            declare_program,
        )
        .await
        .map_err(UnitsRpcApiError::from)?;
        Ok(result)
    }

    async fn send_transaction(
        &self,
        send_transaction: SendTransactionParams,
    ) -> RpcResult<SendTransactionResult> {
        let result = units_handlers_common::send_transaction::send_transaction(
            self.global_ctx.clone(),
            send_transaction,
        )
        .await
        .map_err(UnitsRpcApiError::from)?;
        Ok(result)
    }

    async fn deploy_account(
        &self,
        deploy_account: DeployAccountParams,
    ) -> RpcResult<DeployAccountResult> {
        let result = units_handlers_common::deploy_account::deploy_account(
            self.global_ctx.clone(),
            deploy_account,
        )
        .await
        .map_err(UnitsRpcApiError::from)?;
        Ok(result)
    }
}
