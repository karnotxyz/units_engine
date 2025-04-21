use clap::Args;
use units_primitives::rpc::HexBytes32;
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
    #[arg(env = "UNITS_ENGINE_DECLARE_ACL_ADDRESS", long, value_parser = HexBytes32::from_hex)]
    pub declare_acl_address: HexBytes32,
    /// Private key of the owner wallet.
    /// TODO: HACKY SOLUTION FOR NOW, NEED TO IDEALLY USE KMS
    /// OR SIMIALR SOLUTION FOR STORAGE OF PRIVATE KEYS
    #[arg(env = "UNITS_ENGINE_OWNER_PRIVATE_KEY", long, value_parser = HexBytes32::from_hex)]
    pub owner_private_key: HexBytes32,
    /// Account address corresponding to the private key.
    #[arg(env = "UNITS_ENGINE_ACCOUNT_ADDRESS", long, value_parser = HexBytes32::from_hex)]
    pub account_address: HexBytes32,
}
