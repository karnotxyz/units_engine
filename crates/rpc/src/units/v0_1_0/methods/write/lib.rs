use crate::{units::v0_1_0::api::UnitsWriteRpcApiV0_1_0Server, RpcContext};
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
        unimplemented!()
    }

    async fn send_transaction(
        &self,
        send_transaction: SendTransactionParams,
    ) -> RpcResult<SendTransactionResult> {
        unimplemented!()
    }

    async fn deploy_account(
        &self,
        deploy_account: DeployAccountParams,
    ) -> RpcResult<DeployAccountResult> {
        unimplemented!()
    }
}
