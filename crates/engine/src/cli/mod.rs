use clap::Parser;

mod telemetery;
pub mod rpc;
use rpc::RpcParams;
use telemetery::TelemetryParams;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CliArgs {
    #[command(flatten)]
    pub telemetry: TelemetryParams,
    #[command(flatten)]
    pub rpc: RpcParams,
}
