use std::sync::Arc;

use jsonrpsee::RpcModule;
use units_utils::context::GlobalContext;

mod starknet;

/// A Starknet RPC server for Madara
#[derive(Clone)]
pub struct RpcContext {
    global_ctx: Arc<GlobalContext>,
}

impl RpcContext {
    pub fn new(global_ctx: Arc<GlobalContext>) -> Self {
        Self { global_ctx }
    }
}

/// Returns the RpcModule merged with all the supported RPC versions.
pub fn rpc_api_user(rpc_ctx: &RpcContext) -> anyhow::Result<RpcModule<()>> {
    let mut rpc_api = RpcModule::new(());

    rpc_api.merge(starknet::v0_7_1::StarknetReadRpcApiV0_7_1Server::into_rpc(
        rpc_ctx.clone(),
    ))?;
    rpc_api.merge(starknet::v0_7_1::StarknetWriteRpcApiV0_7_1Server::into_rpc(
        rpc_ctx.clone(),
    ))?;
    rpc_api.merge(starknet::v0_7_1::StarknetTraceRpcApiV0_7_1Server::into_rpc(
        rpc_ctx.clone(),
    ))?;

    Ok(rpc_api)
}

pub fn rpc_api_admin(rpc_ctx: &RpcContext) -> anyhow::Result<RpcModule<()>> {
    let mut rpc_api = RpcModule::new(());

    Ok(rpc_api)
}
