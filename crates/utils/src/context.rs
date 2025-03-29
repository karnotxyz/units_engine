use std::sync::Arc;

use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient};
use url::Url;

use crate::starknet::StarknetProvider;

pub struct GlobalContext {
    starknet_provider: Arc<StarknetProvider>,
}

impl GlobalContext {
    pub fn new(madara_rpc_url: Url) -> anyhow::Result<Self> {
        let starknet_provider = JsonRpcClient::new(HttpTransport::new(madara_rpc_url));
        Ok(Self {
            starknet_provider: Arc::new(starknet_provider),
        })
    }

    pub fn new_with_provider(starknet_provider: Arc<StarknetProvider>) -> Self {
        Self { starknet_provider }
    }

    pub fn starknet_provider(&self) -> Arc<StarknetProvider> {
        self.starknet_provider.clone()
    }
}
