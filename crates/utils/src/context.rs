use std::sync::Arc;

use anyhow::Context;
use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient};

use crate::url::parse_url;

pub struct GlobalContext {
    starknet_provider: Arc<JsonRpcClient<HttpTransport>>,
}

impl GlobalContext {
    pub fn new(madara_rpc_url: String) -> anyhow::Result<Self> {
        let starknet_provider = JsonRpcClient::new(HttpTransport::new(
            parse_url(&madara_rpc_url).context("Invalid madara RPC URL")?,
        ));
        Ok(Self {
            starknet_provider: Arc::new(starknet_provider),
        })
    }

    pub fn starknet_provider(&self) -> Arc<JsonRpcClient<HttpTransport>> {
        self.starknet_provider.clone()
    }
}
