mod cli;
mod service;

use std::sync::Arc;

use crate::cli::CliArgs;
use anyhow::Context;
use clap::Parser;
use service::rpc::RpcService;
use starknet::{
    accounts::{ExecutionEncoding, SingleOwnerAccount},
    core::types::Felt,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::{LocalWallet, SigningKey},
};
use tracing::info;
use units_handlers_starknet::StarknetContext;
use units_primitives::context::GlobalContext;
use units_telemetery::Telemetery;
use units_utils::service::ServiceManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let mut telemetery = Telemetery::new(
        args.telemetry.telemetry_service_name,
        args.telemetry.telemetry_collection_endpoint,
    )?;
    telemetery.setup()?;
    info!("Starting UNITS Engine");

    // Create the global context
    let starknet_ctx = StarknetContext::new(
        args.madara.madara_rpc_url,
        args.madara.declare_acl_address,
        args.madara.owner_private_key,
        args.madara.account_address,
    )
    .await?;
    let global_ctx = Arc::new(GlobalContext::new(Arc::new(Box::new(starknet_ctx))));

    // Create the service manager
    let service_manager = ServiceManager::new();
    service_manager
        .register_service(Arc::new(RpcService::user(
            args.rpc.clone(),
            global_ctx.clone(),
        )))
        .await?;
    service_manager
        .register_service(Arc::new(RpcService::admin(args.rpc, global_ctx.clone())))
        .await?;
    service_manager.start_all().await?;

    // Wait for interrupt signal
    tokio::signal::ctrl_c().await?;
    info!("Received shutdown signal, initiating graceful shutdown");

    // Trigger shutdown on service manager
    service_manager.shutdown_all().await?;
    info!("All services stopped successfully");

    Ok(())
}
