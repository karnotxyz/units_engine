use clap::Args;
use units_utils::url::parse_url;
use url::Url;

/// Parameters used to config madara.
#[derive(Debug, Clone, Args)]
pub struct MadaraParams {
    /// Name of the service.
    #[arg(
        env = "UNITS_ENGINE_MADARA_RPC_URL",
        long,
        value_parser = parse_url
    )]
    pub madara_rpc_url: Url,
    /// Contract address of the declare ACL.
    #[arg(env = "UNITS_ENGINE_DECLARE_ACL_ADDRESS", long)]
    pub declare_acl_address: String,
    /// Private key of the owner wallet.
    /// TODO: HACKY SOLUTION FOR NOW, NEED TO IDEALLY USE KMS
    /// OR SIMIALR SOLUTION FOR STORAGE OF PRIVATE KEYS
    #[arg(env = "UNITS_ENGINE_OWNER_PRIVATE_KEY", long)]
    pub owner_private_key: String,
    /// Account address corresponding to the private key.
    #[arg(env = "UNITS_ENGINE_ACCOUNT_ADDRESS", long)]
    pub account_address: String,
}
