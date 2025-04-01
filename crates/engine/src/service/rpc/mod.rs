use core::fmt;
use std::{collections::HashMap, fmt::Display, sync::Arc};
use tokio::sync::{broadcast, Mutex};

use jsonrpsee::server::ServerHandle;

use metrics::RpcMetrics;
use rpc_version::RpcVersion;
use server::{start_server, ServerConfig};
use units_rpc::{rpc_api_admin, rpc_api_user, RpcContext};
use units_utils::{context::GlobalContext, service::Service};

use crate::cli::rpc::RpcParams;

use self::server::rpc_api_build;

mod metrics;
mod middleware;
mod rpc_version;
mod server;

const RPC_VERSION_DEFAULT_STARKNET: RpcVersion = RpcVersion::new(0, 7, 1);
const RPC_VERSION_DEFAULT_UNITS: RpcVersion = RpcVersion::new(0, 1, 0);
const RPC_VERSION_DEFAULT_ADMIN: RpcVersion = RpcVersion::new(0, 1, 0);

#[derive(Clone)]
pub enum RpcAccess {
    User,
    Admin,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RpcType {
    Starknet,
    Units,
    Admin,
}

impl RpcType {
    pub fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "starknet" => Some(Self::Starknet),
            "units" => Some(Self::Units),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

impl Display for RpcAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcAccess::User => write!(f, "user"),
            RpcAccess::Admin => write!(f, "admin"),
        }
    }
}

pub struct RpcService {
    config: RpcParams,
    global_ctx: Arc<GlobalContext>,
    server_handle: Arc<Mutex<Option<ServerHandle>>>,
    rpc_access: RpcAccess,
}

impl RpcService {
    pub fn user(config: RpcParams, global_ctx: Arc<GlobalContext>) -> Self {
        Self {
            config,
            global_ctx,
            server_handle: Arc::new(Mutex::new(None)),
            rpc_access: RpcAccess::User,
        }
    }

    pub fn admin(config: RpcParams, global_ctx: Arc<GlobalContext>) -> Self {
        Self {
            config,
            global_ctx,
            server_handle: Arc::new(Mutex::new(None)),
            rpc_access: RpcAccess::Admin,
        }
    }
}

#[async_trait::async_trait]
impl Service for RpcService {
    async fn start(&self, shutdown_rx: broadcast::Receiver<()>) -> anyhow::Result<()> {
        let config = self.config.clone();
        let global_ctx: Arc<GlobalContext> = Arc::clone(&self.global_ctx);
        let rpc_type = self.rpc_access.clone();

        let (stop_handle, server_handle) = jsonrpsee::server::stop_channel();

        let mut handle = self.server_handle.lock().await;
        *handle = Some(server_handle);
        drop(handle);

        let starknet = RpcContext::new(global_ctx.clone());
        let metrics = RpcMetrics::register()?;

        let server_config = {
            let (name, addr, api_rpc, rpc_version_default) = match rpc_type {
                RpcAccess::User => (
                    "JSON-RPC".to_string(),
                    config.addr_user(),
                    rpc_api_user(&starknet)?,
                    HashMap::from([
                        (RpcType::Starknet, RPC_VERSION_DEFAULT_STARKNET),
                        (RpcType::Units, RPC_VERSION_DEFAULT_UNITS),
                    ]),
                ),
                RpcAccess::Admin => (
                    "JSON-RPC (Admin)".to_string(),
                    config.addr_admin(),
                    rpc_api_admin(&starknet)?,
                    HashMap::from([(RpcType::Admin, RPC_VERSION_DEFAULT_ADMIN)]),
                ),
            };
            let methods = rpc_api_build("rpc", api_rpc).into();

            ServerConfig {
                name,
                addr,
                batch_config: config.batch_config(),
                max_connections: config.rpc_max_connections,
                max_payload_in_mb: config.rpc_max_request_size,
                max_payload_out_mb: config.rpc_max_response_size,
                max_subs_per_conn: config.rpc_max_subscriptions_per_connection,
                message_buffer_capacity: config.rpc_message_buffer_capacity_per_connection,
                methods,
                metrics,
                cors: config.cors(),
                rpc_version_default,
            }
        };

        start_server(server_config, shutdown_rx, stop_handle).await?;

        anyhow::Ok(())
    }

    async fn shutdown(&self) -> anyhow::Result<()> {
        // Graceful shutdown should be handled by the server
        anyhow::Ok(())
    }

    fn name(&self) -> String {
        self.rpc_access.to_string()
    }
}
