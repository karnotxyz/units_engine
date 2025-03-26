use clap::Parser;

pub mod madara;
pub mod rpc;
mod telemetery;
use madara::MadaraParams;
use rpc::RpcParams;
use telemetery::TelemetryParams;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CliArgs {
    #[command(flatten)]
    pub telemetry: TelemetryParams,
    #[command(flatten)]
    pub rpc: RpcParams,
    #[command(flatten)]
    pub madara: MadaraParams,
}
