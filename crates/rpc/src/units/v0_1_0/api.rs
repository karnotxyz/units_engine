use jsonrpsee::core::RpcResult;
use units_primitives::rpc::{
    DeclareProgramParams, DeclareTransactionResult, DeployAccountParams, DeployAccountResult,
    GetChainIdResult, GetNonceParams, GetNonceResult, GetProgramParams, GetProgramResult,
    GetTransactionReceiptParams, GetTransactionReceiptResult, SendTransactionParams,
    SendTransactionResult,
};
use units_proc_macros::versioned_rpc;

#[versioned_rpc("V0_1_0", "units")]
pub trait UnitsWriteRpcApi {
    /// Declare a new program
    #[method(name = "declareProgram")]
    async fn declare_program(
        &self,
        declare_program: DeclareProgramParams,
    ) -> RpcResult<DeclareTransactionResult>;

    /// Send a transaction
    #[method(name = "sendTransaction")]
    async fn send_transaction(
        &self,
        send_transaction: SendTransactionParams,
    ) -> RpcResult<SendTransactionResult>;

    /// Deploy a new account
    #[method(name = "deployAccount")]
    async fn deploy_account(
        &self,
        deploy_account: DeployAccountParams,
    ) -> RpcResult<DeployAccountResult>;
}

#[versioned_rpc("V0_1_0", "units")]
pub trait UnitsReadRpcApi {
    /// Get a program by its hash
    #[method(name = "getProgram")]
    async fn get_program(&self, get_program: GetProgramParams) -> RpcResult<GetProgramResult>;

    /// Get the nonce for an account
    #[method(name = "getNonce")]
    async fn get_nonce(&self, get_nonce: GetNonceParams) -> RpcResult<GetNonceResult>;

    /// Get a transaction receipt
    #[method(name = "getTransactionReceipt")]
    async fn get_transaction_receipt(
        &self,
        get_transaction_receipt: GetTransactionReceiptParams,
    ) -> RpcResult<GetTransactionReceiptResult>;

    /// Get the chain ID
    #[method(name = "getChainId")]
    async fn get_chain_id(&self) -> RpcResult<GetChainIdResult>;
}
