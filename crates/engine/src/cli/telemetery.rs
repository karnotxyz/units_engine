use clap::Args;
use units_utils::url::parse_url;
use url::Url;

/// Parameters used to config telemetry.
#[derive(Debug, Clone, Args)]
pub struct TelemetryParams {
    /// Name of the service.
    #[arg(
        env = "UNITS_ENGINE_ANALYTICS_SERVICE_NAME",
        long,
        alias = "analytics",
        default_value = "units_engine"
    )]
    pub telemetry_service_name: String,

    /// Endpoint of the analytics server.
    #[arg(env = "OTEL_EXPORTER_OTLP_ENDPOINT", long, value_parser = parse_url, default_value = None)]
    pub telemetry_collection_endpoint: Option<Url>,
}
