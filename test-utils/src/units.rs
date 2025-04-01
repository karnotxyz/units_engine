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
    madara::MadaraRunner,
    port::{get_free_port, PortAllocation},
    workspace::WORKSPACE_ROOT,
};

const UNITS_BINARY_PATH: &str = "target/debug/units_engine";

pub struct UnitsRunner {
    process: Option<Child>,
    madara: Option<MadaraRunner>,
    port_allocation: Option<PortAllocation>,
}

impl UnitsRunner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            process: None,
            madara: None,
            port_allocation: None,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // First start Madara
        let mut madara = MadaraRunner::new()?;
        madara.run().await?;
        let madara_port = madara.port().unwrap();
        self.madara = Some(madara);

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
        let mut process = Command::new(units_path)
            .arg("--rpc-port")
            .arg(units_port.to_string())
            .arg("--madara-rpc-url")
            .arg(format!("http://localhost:{}", madara_port))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Get handles to stdout and stderr
        let stdout = process.stdout.take().unwrap();
        let stderr = process.stderr.take().unwrap();

        // Spawn threads to handle stdout and stderr
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("[UNITS] {}", line);
                }
            }
        });

        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    eprintln!("[UNITS] {}", line);
                }
            }
        });

        self.process = Some(process);

        // Wait for the Units service to be ready
        let client = Client::new();
        let url = format!("http://localhost:{}/health", units_port);

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

impl Drop for UnitsRunner {
    fn drop(&mut self) {
        // Kill the Units process
        if let Some(mut process) = self.process.take() {
            println!("Shutting down Units engine...");
            let _ = process.kill();
            let _ = process.wait();
        }

        // Madara will be automatically killed when dropped
        if self.madara.take().is_some() {
            println!("Cleaning up Madara instance...");
        }
        println!("Units runner cleaned up.");
    }
}
