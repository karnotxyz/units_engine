#![allow(clippy::print_stdout, clippy::print_stderr)]

use crate::{StarknetProvider, StarknetWallet};
use anyhow::{anyhow, Result};
use reqwest::Client;
use rstest::*;
use starknet::core::crypto::Signature;
use starknet::core::types::Felt;
use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient};
use starknet::signers::SigningKey;
use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::Duration,
};
use tokio::time::sleep;
use units_tests_utils::port::{get_free_port, PortAllocation};
use units_tests_utils::units::ChainBackend;
use url::Url;
use uuid::Uuid;

const MADARA_DOCKER_IMAGE: &str = "ghcr.io/madara-alliance/madara:manual-2ba7dbd";

pub struct MadaraRunner {
    port_allocation: Option<PortAllocation>,
    process: Option<Child>,
    temp_dir: Option<PathBuf>,
    container_id: Option<String>,
}

impl MadaraRunner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            port_allocation: None,
            process: None,
            temp_dir: None,
            container_id: None,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Get a free port
        let port_allocation = get_free_port()?;
        let port = port_allocation.port();

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join(format!("madara-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir)?;

        // Pull the latest Madara Docker image
        println!("Pulling Madara Docker image: {}", MADARA_DOCKER_IMAGE);
        let pull_output = Command::new("docker")
            .arg("pull")
            .arg("--platform")
            .arg("amd64")
            .arg(MADARA_DOCKER_IMAGE)
            .output()?;

        if !pull_output.status.success() {
            return Err(anyhow!(
                "Failed to pull Madara Docker image: {}",
                String::from_utf8_lossy(&pull_output.stderr)
            ));
        }

        // Generate a unique container name
        let container_name = format!("madara-test-{}", Uuid::new_v4());

        // Start the Madara Docker container
        let mut process = Command::new("docker")
            .arg("run")
            .arg("--rm")
            .arg("--name")
            .arg(&container_name)
            .arg("-p")
            .arg(format!("{}:9944", port))
            .arg("-v")
            .arg(format!("{}:/data", temp_dir.to_str().unwrap()))
            .arg(MADARA_DOCKER_IMAGE)
            .arg("--devnet")
            .arg("--rpc-port")
            .arg("9944")
            .arg("--rpc-external") // Use the internal port, Docker will map it
            .arg("--base-path")
            .arg("/data")
            .arg("--l1-gas-price")
            .arg("1")
            .arg("--blob-gas-price")
            .arg("1")
            .arg("--strk-per-eth")
            .arg("1")
            .arg("--chain-config-override")
            .arg("block_time=2s,l2_gas_price.type=fixed,l2_gas_price.price=2500")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Get handles to stdout and stderr
        let stdout = process.stdout.take().unwrap();
        let stderr = process.stderr.take().unwrap();

        // Spawn threads to handle stdout and stderr
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                println!("[MADARA] {}", line);
            }
        });

        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("[MADARA] {}", line);
            }
        });

        self.process = Some(process);
        self.port_allocation = Some(port_allocation);
        self.temp_dir = Some(temp_dir);
        self.container_id = Some(container_name);

        // Wait for Madara to be ready by polling the health endpoint
        let client = Client::new();
        let url = format!("http://localhost:{}/health", port);

        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 10; // Increased timeout for Docker startup

        while attempts < MAX_ATTEMPTS {
            match client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    println!("Madara is ready on port {}", port);
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

    /// Returns the RPC URL of the Madara node, if it has been started
    pub fn rpc_url(&self) -> Option<Url> {
        self.port_allocation
            .as_ref()
            .map(|alloc| Url::parse(&format!("http://localhost:{}", alloc.port())).unwrap())
    }
}

impl Drop for MadaraRunner {
    fn drop(&mut self) {
        // Stop the Docker container
        if let Some(container_id) = self.container_id.take() {
            println!("Stopping Madara container: {}", container_id);
            let _ = Command::new("docker")
                .arg("stop")
                .arg(&container_id)
                .output();
        }

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

/// Used in `UnitsRunner` to start a Madara node
impl ChainBackend for MadaraRunner {
    fn add_args(&self, command: &mut Command) {
        command
            .arg("--madara-rpc-url")
            .arg(self.rpc_url().unwrap().to_string())
            .arg("--declare-acl-address")
            .arg("0x0")
            .arg("--owner-private-key")
            .arg("0x0")
            .arg("--account-address")
            .arg("0x0");
    }
}
/// Returns a running Madara node and configured Starknet provider
#[fixture]
pub async fn madara_node() -> (MadaraRunner, Arc<StarknetProvider>) {
    let mut runner = MadaraRunner::new().unwrap();
    runner.run().await.unwrap();

    let rpc_url = runner.rpc_url().unwrap();
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(rpc_url)));

    (runner, provider)
}

#[derive(Debug, Clone)]
pub struct StarknetWalletWithPrivateKey {
    pub account: Arc<StarknetWallet>,
    pub private_key: Felt,
}

impl StarknetWalletWithPrivateKey {
    pub fn sign_message(&self, message: &Felt) -> Signature {
        let signer = SigningKey::from_secret_scalar(self.private_key);
        signer.sign(message).unwrap()
    }
}

/// Returns a running Madara node, configured Starknet provider, and a vector of deployed accounts
#[fixture]
#[cfg(test)]
pub async fn madara_node_with_accounts(
    #[default(1)] num_accounts: u32,
) -> (
    MadaraRunner,
    Arc<StarknetProvider>,
    Vec<StarknetWalletWithPrivateKey>,
) {
    use super::starknet::PREDEPLOYED_ACCOUNT_CLASS_HASH;
    use crate::utils::{deploy_account, BuildAccount};

    let (runner, provider) = madara_node().await;

    let mut accounts = Vec::new();
    // start from 1 because 0 is an invalid private key
    for i in 1..=num_accounts {
        let private_key = Felt::from(i);
        let account = deploy_account(
            provider.clone(),
            private_key,
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_CLASS_HASH),
        )
        .await
        .expect("Failed to deploy account")
        .wait_for_receipt_and_build_account(provider.clone(), private_key)
        .await
        .expect("Failed to build account");
        accounts.push(StarknetWalletWithPrivateKey {
            account,
            private_key,
        });
    }

    (runner, provider, accounts)
}
