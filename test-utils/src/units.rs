#![allow(clippy::print_stdout, clippy::print_stderr)]

use anyhow::{anyhow, Result};
use reqwest::Client;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    thread,
};
use tokio::time::{sleep, Duration};
use url::Url;

use crate::{
    port::{get_free_port, PortAllocation},
    workspace::WORKSPACE_ROOT,
};

const UNITS_BINARY_PATH: &str = "target/debug/units_engine";

pub trait ChainBackend {
    fn add_args(&self, command: &mut Command);
}

pub struct UnitsRunner<T>
where
    T: ChainBackend,
{
    process: Option<Child>,
    chain_backend: T,
    port_allocation: Option<PortAllocation>,
}

impl<T: ChainBackend> UnitsRunner<T> {
    pub fn new(chain_backend: T) -> Result<Self> {
        Ok(Self {
            process: None,
            chain_backend,
            port_allocation: None,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // First start the chain backend

        // Get a free port for Units
        let port_allocation = get_free_port()?;
        let units_port = port_allocation.port();
        self.port_allocation = Some(port_allocation);

        // Build the project
        println!("Building the project...");
        let build_status = Command::new("cargo")
            .arg("build")
            .current_dir(&*WORKSPACE_ROOT)
            .status()?;

        if !build_status.success() {
            return Err(anyhow!("Failed to build the project"));
        }

        // Start the Units process
        println!("Starting Units engine...");
        let units_path = WORKSPACE_ROOT.join(UNITS_BINARY_PATH);
        let mut command = Command::new(units_path);
        command.arg("--rpc-port").arg(units_port.to_string());
        self.chain_backend.add_args(&mut command);
        let mut process = command
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
                println!("[UNITS] {line}");
            }
        });

        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("[UNITS] {line}");
            }
        });

        self.process = Some(process);

        // Wait for the Units service to be ready
        let client = Client::new();
        let url = format!("http://localhost:{units_port}/health");

        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 10;

        while attempts < MAX_ATTEMPTS {
            match client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    println!("Units engine is ready!");
                    return Ok(());
                }
                _ => {
                    sleep(Duration::from_secs(1)).await;
                    attempts += 1;
                }
            }
        }

        Err(anyhow!(
            "Units engine failed to start after {} seconds",
            MAX_ATTEMPTS
        ))
    }

    /// Returns the port number that Units is running on, if it has been started
    pub fn port(&self) -> Option<u16> {
        self.port_allocation.as_ref().map(|alloc| alloc.port())
    }

    /// Returns the RPC URL of the Units service, if it has been started
    pub fn rpc_url(&self) -> Option<Url> {
        self.port_allocation
            .as_ref()
            .map(|alloc| Url::parse(&format!("http://localhost:{}", alloc.port())).unwrap())
    }
}

impl<T: ChainBackend> Drop for UnitsRunner<T> {
    fn drop(&mut self) {
        // Kill the Units process
        if let Some(mut process) = self.process.take() {
            println!("Shutting down Units engine...");
            let _ = process.kill();
            let _ = process.wait();
        }

        // Chain backend will be automatically killed when dropped
        println!("Units runner cleaned up.");
    }
}
