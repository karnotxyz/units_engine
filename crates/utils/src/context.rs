use std::sync::Arc;

use starknet::{
    accounts::{ExecutionEncoding, SingleOwnerAccount},
    core::types::Felt,
    providers::{jsonrpc::HttpTransport, JsonRpcClient},
    signers::{LocalWallet, SigningKey},
};
use url::Url;

use crate::starknet::{StarknetProvider, StarknetWallet};

pub struct GlobalContext {
    starknet_provider: Arc<StarknetProvider>,
    declare_acl_address: Felt,
    owner_wallet: Arc<StarknetWallet>,
}

impl GlobalContext {
    pub fn new(
        madara_rpc_url: Url,
        declare_acl_address: Felt,
        owner_wallet: Arc<StarknetWallet>,
    ) -> anyhow::Result<Self> {
        let starknet_provider = JsonRpcClient::new(HttpTransport::new(madara_rpc_url));
        Ok(Self {
            starknet_provider: Arc::new(starknet_provider),
            declare_acl_address,
            owner_wallet,
        })
    }

    pub fn new_with_provider(
        starknet_provider: Arc<StarknetProvider>,
        declare_acl_address: Felt,
        owner_wallet: Arc<StarknetWallet>,
    ) -> Self {
        Self {
            starknet_provider,
            declare_acl_address,
            owner_wallet,
        }
    }

    pub fn starknet_provider(&self) -> Arc<StarknetProvider> {
        self.starknet_provider.clone()
    }

    pub fn declare_acl_address(&self) -> Felt {
        self.declare_acl_address
    }

    pub fn owner_wallet(&self) -> Arc<StarknetWallet> {
        self.owner_wallet.clone()
    }
}
