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
}
