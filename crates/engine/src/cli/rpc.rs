// Taken from https://github.com/madara-alliance/madara/blob/2267214bcb2142b6eddf990105008f9e467425e8/madara/crates/node/src/cli/rpc.rs

use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

use jsonrpsee::server::BatchRequestConfig;

/// The default port.
pub const RPC_DEFAULT_PORT: u16 = 9945;
/// Default port for sensitive RPC methods
pub const RPC_DEFAULT_PORT_ADMIN: u16 = 9946;
/// The default max number of subscriptions per connection.
pub const RPC_DEFAULT_MAX_SUBS_PER_CONN: u32 = 1024;
/// The default max request size in MB.
pub const RPC_DEFAULT_MAX_REQUEST_SIZE_MB: u32 = 15;
/// The default max response size in MB.
pub const RPC_DEFAULT_MAX_RESPONSE_SIZE_MB: u32 = 15;
/// The default number of connection..
pub const RPC_DEFAULT_MAX_CONNECTIONS: u32 = 100;
/// The default number of messages the RPC server
/// is allowed to keep in memory per connection.
pub const RPC_DEFAULT_MESSAGE_CAPACITY_PER_CONN: u32 = 64;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Cors {
    /// All hosts allowed.
    All,
    /// Only hosts on the list are allowed.
    List(Vec<String>),
}

impl FromStr for Cors {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut is_all = false;
        let mut origins = Vec::new();
        for part in s.split(',') {
            match part {
                "all" | "*" => {
                    is_all = true;
                    break;
                }
                other => origins.push(other.to_owned()),
            }
        }

        if is_all {
            Ok(Cors::All)
        } else {
            Ok(Cors::List(origins))
        }
    }
}

#[derive(Clone, Debug, clap::Args, Deserialize, Serialize)]
pub struct RpcParams {
    /// Disables the user RPC endpoint. This includes all methods which are part
    /// of the official starknet specs.
    #[arg(env = "UNITS_ENGINE_RPC_DISABLE", long, default_value_t = false)]
    pub rpc_disable: bool,

    /// Exposes the user RPC endpoint on address 0.0.0.0. This generally means
    /// that RPC methods will be accessible from the outside world.
    #[arg(env = "UNITS_ENGINE_RPC_EXTERNAL", long, default_value_t = false)]
    pub rpc_external: bool,

    /// Enables the admin RPC endpoint. This includes additional RPC methods
    /// which are not part of the official specs and can be used by node admins
    /// to control their node at a distance. By default, this is exposed on
    /// localhost.
    #[arg(env = "UNITS_ENGINE_RPC_ADMIN", long, default_value_t = false)]
    pub rpc_admin: bool,

    /// Exposes the admin RPC endpoint on address 0.0.0.0. This is especially
    /// useful when running Madara from inside a docker container. Be very
    /// careful however when exposing this endpoint to the outside world.
    #[arg(env = "UNITS_ENGINE_RPC_ADMIN_EXTERNAL", long, default_value_t = false)]
    pub rpc_admin_external: bool,

    /// Set the maximum RPC request payload size for both HTTP and WebSockets in megabytes.
    #[arg(env = "UNITS_ENGINE_RPC_MAX_REQUEST_SIZE", long, default_value_t = RPC_DEFAULT_MAX_REQUEST_SIZE_MB)]
    pub rpc_max_request_size: u32,

    /// Set the maximum RPC response payload size for both HTTP and WebSockets in megabytes.
    #[arg(env = "UNITS_ENGINE_RPC_MAX_RESPONSE_SIZE", long, default_value_t = RPC_DEFAULT_MAX_RESPONSE_SIZE_MB)]
    pub rpc_max_response_size: u32,

    /// Set the maximum concurrent subscriptions per connection.
    #[arg(env = "UNITS_ENGINE_RPC_MAX_SUBSCRIPTIONS_PER_CONNECTION", long, default_value_t = RPC_DEFAULT_MAX_SUBS_PER_CONN)]
    pub rpc_max_subscriptions_per_connection: u32,

    /// The RPC port to listen at.
    #[arg(env = "UNITS_ENGINE_RPC_PORT", long, value_name = "PORT", default_value_t = RPC_DEFAULT_PORT)]
    pub rpc_port: u16,

    /// The RPC port to listen at for admin RPC calls.
    #[arg(env = "UNITS_ENGINE_RPC_PORT_ADMIN", long, value_name = "ADMIN PORT", default_value_t = RPC_DEFAULT_PORT_ADMIN)]
    pub rpc_admin_port: u16,

    /// Maximum number of RPC server connections at a given time.
    #[arg(env = "UNITS_ENGINE_RPC_MAX_CONNECTIONS", long, value_name = "COUNT", default_value_t = RPC_DEFAULT_MAX_CONNECTIONS)]
    pub rpc_max_connections: u32,

    /// The maximum number of messages that can be kept in memory at a given time, per connection.
    /// The server enforces backpressure, and this buffering is useful when the client cannot keep up with our server.
    #[arg(env = "UNITS_ENGINE_RPC_MESSAGE_BUFFER_CAPACITY_PER_CONNECTION", long, default_value_t = RPC_DEFAULT_MESSAGE_CAPACITY_PER_CONN)]
    pub rpc_message_buffer_capacity_per_connection: u32,

    /// Disable RPC batch requests.
    #[arg(env = "UNITS_ENGINE_RPC_DISABLE_BATCH_REQUESTS", long, alias = "rpc_no_batch_requests", conflicts_with_all = &["rpc_max_batch_request_len"])]
    pub rpc_disable_batch_requests: bool,

    /// Limit the max length for an RPC batch request.
    #[arg(env = "UNITS_ENGINE_RPC_MAX_BATCH_REQUEST_LEN", long, conflicts_with_all = &["rpc_disable_batch_requests"], value_name = "LEN")]
    pub rpc_max_batch_request_len: Option<u32>,

    /// Specify browser *origins* allowed to access the HTTP & WebSocket RPC
    /// servers.
    ///
    /// For most purposes, an origin can be thought of as just `protocol://domain`.
    /// Default behavior depends on `rpc_external`:
    ///
    ///     - If rpc_external is set, CORS will default to allow all incoming
    ///     addresses.
    ///     - If rpc_external is not set, CORS will default to allow only
    ///     connections from `localhost`.
    ///
    /// > If the rpcs are permissive, the same will be true for core, and
    /// > vise-versa.
    ///
    /// This argument is a comma separated list of origins, or the special `all`
    /// value.
    ///
    /// Learn more about CORS and web security at
    /// <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS>.
    #[arg(env = "UNITS_ENGINE_RPC_CORS", long, value_name = "ORIGINS")]
    pub rpc_cors: Option<Cors>,
}

impl RpcParams {
    pub fn cors(&self) -> Option<Vec<String>> {
        let cors = self.rpc_cors.clone().unwrap_or_else(|| {
            if self.rpc_external {
                Cors::All
            } else {
                Cors::List(vec![
                    "http://localhost:*".into(),
                    "http://127.0.0.1:*".into(),
                    "https://localhost:*".into(),
                    "https://127.0.0.1:*".into(),
                ])
            }
        });

        match cors {
            Cors::All => None,
            Cors::List(ls) => Some(ls),
        }
    }

    pub fn addr_user(&self) -> SocketAddr {
        let listen_addr = if self.rpc_external {
            Ipv4Addr::UNSPECIFIED // listen on 0.0.0.0
        } else {
            Ipv4Addr::LOCALHOST
        };

        SocketAddr::new(listen_addr.into(), self.rpc_port)
    }

    pub fn addr_admin(&self) -> SocketAddr {
        let listen_addr = if self.rpc_admin_external {
            Ipv4Addr::UNSPECIFIED // listen on 0.0.0.0
        } else {
            Ipv4Addr::LOCALHOST
        };

        SocketAddr::new(listen_addr.into(), self.rpc_admin_port)
    }

    pub fn batch_config(&self) -> BatchRequestConfig {
        if self.rpc_disable_batch_requests {
            BatchRequestConfig::Disabled
        } else if let Some(l) = self.rpc_max_batch_request_len {
            BatchRequestConfig::Limit(l)
        } else {
            BatchRequestConfig::Unlimited
        }
    }
}
