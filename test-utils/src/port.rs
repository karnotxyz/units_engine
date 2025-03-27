use anyhow::Result;
use once_cell::sync::Lazy;
use std::{
    collections::HashSet,
    net::{SocketAddr, TcpListener},
    sync::Mutex,
};

// Global set to track allocated ports
static ALLOCATED_PORTS: Lazy<Mutex<HashSet<u16>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// Represents a port allocation that will be freed when dropped
pub struct PortAllocation {
    port: u16,
}

impl PortAllocation {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for PortAllocation {
    fn drop(&mut self) {
        let mut ports = ALLOCATED_PORTS.lock().unwrap();
        ports.remove(&self.port);
    }
}

/// Gets an available port and returns a PortAllocation that will free the port when dropped
pub fn get_free_port() -> Result<PortAllocation> {
    let mut ports = ALLOCATED_PORTS.lock().unwrap();

    // Try ports in the range 1024-9999
    for port in 1024..=9999 {
        if ports.contains(&port) {
            continue;
        }

        // Try to bind to the port to check if it's available
        if let Ok(_) = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))) {
            ports.insert(port);
            return Ok(PortAllocation { port });
        }
    }

    anyhow::bail!("No free ports available")
}
