use crate::utils::port::{get_free_port, PortAllocation};
use anyhow::{anyhow, Result};
use reqwest::Client;
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command},
    time::Duration,
};
use tokio::time::sleep;
use uuid::Uuid;

const MADARA_BINARY_PATH: &str = "build/madara";

pub struct MadaraRunner {
    port_allocation: Option<PortAllocation>,
    process: Option<Child>,
    temp_dir: Option<PathBuf>,
}

impl MadaraRunner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            port_allocation: None,
            process: None,
            temp_dir: None,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Get a free port
        let port_allocation = get_free_port()?;
        let port = port_allocation.port();

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join(format!("madara-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir)?;

        // Start the Madara process
        let process = Command::new(format!(
            "{}/{}",
            std::env::var("CARGO_MANIFEST_DIR").unwrap(),
            MADARA_BINARY_PATH
        ))
        .arg("--devnet")
        .arg("--rpc-port")
        .arg(port.to_string())
        .arg("--base-path")
        .arg(temp_dir.to_str().unwrap())
        .arg("--gas-price")
        .arg("0")
        .arg("--blob-gas-price")
        .arg("0")
        .arg("--strk-gas-price")
        .arg("0")
        .arg("--strk-blob-gas-price")
        .arg("0")
        .arg("--chain-config-override")
        .arg("pending_block_update_time=200ms")
        .spawn()?;

        self.process = Some(process);
        self.port_allocation = Some(port_allocation);
        self.temp_dir = Some(temp_dir);

        // Wait for Madara to be ready by polling the health endpoint
        let client = Client::new();
        let url = format!("http://localhost:{}/health", port);

        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 10; // Try for 60 seconds

        while attempts < MAX_ATTEMPTS {
            match client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    return Ok(());
                }
                _ => {
                    sleep(Duration::from_secs(1)).await;
                    attempts += 1;
                }
            }
        }

        Err(anyhow!(
            "Madara failed to start after {} seconds",
            MAX_ATTEMPTS
        ))
    }

    /// Returns the port number that Madara is running on, if it has been started
    pub fn port(&self) -> Option<u16> {
        self.port_allocation.as_ref().map(|alloc| alloc.port())
    }
}

impl Drop for MadaraRunner {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            // Try to kill the process gracefully
            let _ = process.kill();
            let _ = process.wait(); // Wait for the process to be killed
        }
        // Clean up the temporary directory
        if let Some(temp_dir) = self.temp_dir.take() {
            let _ = fs::remove_dir_all(temp_dir);
        }
        // Port will be automatically freed when port_allocation is dropped
    }
}
