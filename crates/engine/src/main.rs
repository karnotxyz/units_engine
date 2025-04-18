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
use units_telemetery::Telemetery;
use units_utils::{context::GlobalContext, service::ServiceManager};

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
    let starknet_provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        args.madara.madara_rpc_url,
    )));
    let declare_acl_address = Felt::from_hex(args.madara.declare_acl_address.as_str())
        .context("Declare ACL address is not valid")?;
    let signer = SigningKey::from_secret_scalar(
        Felt::from_hex(args.madara.owner_private_key.as_str())
            .context("Owner private key is not valid")?,
    );
    let local_wallet = Arc::new(LocalWallet::from(signer));
    let chain_id = starknet_provider
        .chain_id()
        .await
        .context("Failed to get chain id")?;
    let account_address = Felt::from_hex(args.madara.account_address.as_str())
        .context("Account address is not valid")?;
    let account = SingleOwnerAccount::new(
        starknet_provider.clone(),
        local_wallet,
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );
    let global_ctx = Arc::new(GlobalContext::new_with_provider(
        starknet_provider.clone(),
        declare_acl_address,
        Arc::new(account),
    ));

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
