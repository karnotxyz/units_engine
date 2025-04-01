use async_trait::async_trait;
use futures::future;
use std::collections::HashMap;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{error, info, warn};

/// Trait that must be implemented by all services
#[async_trait]
pub trait Service: Send + Sync + 'static {
    /// Start the service
    async fn start(&self, shutdown_rx: broadcast::Receiver<()>) -> anyhow::Result<()>;

    /// Gracefully shutdown the service
    async fn shutdown(&self) -> anyhow::Result<()>;

    /// Get the name of the service
    fn name(&self) -> String;
}

type DynService = Arc<dyn Service>;

/// Manages the lifecycle of multiple services
pub struct ServiceManager {
    services: Arc<Mutex<HashMap<String, DynService>>>,
    handles: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    shutdown_tx: broadcast::Sender<()>,
    shutdown_rx: Arc<Mutex<broadcast::Receiver<()>>>,
}

impl ServiceManager {
    /// Create a new ServiceManager
    pub fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        ServiceManager {
            services: Arc::new(Mutex::new(HashMap::new())),
            handles: Arc::new(Mutex::new(HashMap::new())),
            shutdown_tx,
            shutdown_rx: Arc::new(Mutex::new(shutdown_rx)),
        }
    }

    /// Register a new service with the manager
    pub async fn register_service<S>(&self, service: Arc<S>) -> anyhow::Result<()>
    where
        S: Service,
    {
        let name = service.name();
        let mut services = self.services.lock().await;
        if services.contains_key(&name) {
            return Err(anyhow::anyhow!("Service {} is already registered", name));
        }
        services.insert(name, service);
        Ok(())
    }

    /// Start all registered services
    pub async fn start_all(&self) -> anyhow::Result<()> {
        let services = self.services.lock().await;
        let mut handles = self.handles.lock().await;
        for (name, service) in services.iter() {
            let shutdown_rx = self.get_shutdown_signal().await;
            let service_clone: DynService = Arc::clone(service);
            let handle = tokio::spawn(async move {
                if let Err(e) = service_clone.start(shutdown_rx).await {
                    error!(
                        error = %e,
                        service.name = service_clone.name(),
                        "Error starting service"
                    );
                }
            });
            handles.insert(name.clone(), handle);
        }
        Ok(())
    }

    /// Initiate graceful shutdown of all services
    /// Will force shutdown after 10 seconds if services haven't stopped
    pub async fn shutdown_all(&self) -> anyhow::Result<()> {
        // Signal shutdown
        let _ = self.shutdown_tx.send(());

        // Wait for all service handles to complete
        let mut handles = self.handles.lock().await;
        let handle_futures: Vec<_> = handles
            .drain()
            .map(|(name, handle)| {
                let name = name.clone();
                async move {
                    if let Err(e) = handle.await {
                        error!(
                            error = %e,
                            service.name = name,
                            "Error waiting for service to complete"
                        );
                    }
                }
            })
            .collect();

        // Give handles 10 seconds to complete
        match timeout(Duration::from_secs(10), future::join_all(handle_futures)).await {
            Ok(_) => info!("All service handles completed"),
            Err(_) => {
                warn!("Some service handles did not complete within 10 seconds - forcing abort")
            }
        }

        // Wait for all services to shutdown and cleanup
        let services = self.services.lock().await;
        let shutdown_futures: Vec<_> = services
            .values()
            .map(|service| {
                let service_clone: DynService = Arc::clone(service);
                async move {
                    if let Err(e) = service_clone.shutdown().await {
                        error!(
                            error = %e,
                            service.name = service_clone.name(),
                            "Error shutting down service"
                        );
                    }
                }
            })
            .collect();

        // Wait for all services to shutdown with timeout
        match timeout(Duration::from_secs(10), future::join_all(shutdown_futures)).await {
            Ok(_) => info!("All services shut down gracefully"),
            Err(_) => warn!("Some services did not shut down within 10 seconds - forcing shutdown"),
        }

        Ok(())
    }

    /// Get the shutdown receiver for listening to shutdown signals
    pub async fn get_shutdown_signal(&self) -> broadcast::Receiver<()> {
        let rx = self.shutdown_rx.lock().await;
        rx.resubscribe()
    }
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::time::sleep;

    struct TestService {
        name: String,
        shutdown_delay: Duration,
        was_shutdown: Arc<AtomicBool>,
    }

    impl TestService {
        fn new(name: &str, shutdown_delay: Duration) -> Self {
            TestService {
                name: name.to_string(),
                shutdown_delay,
                was_shutdown: Arc::new(AtomicBool::new(false)),
            }
        }

        fn was_shutdown(&self) -> bool {
            self.was_shutdown.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Service for TestService {
        async fn start(&self, _shutdown_rx: broadcast::Receiver<()>) -> anyhow::Result<()> {
            Ok(())
        }

        async fn shutdown(&self) -> anyhow::Result<()> {
            sleep(self.shutdown_delay).await;
            self.was_shutdown.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn name(&self) -> String {
            self.name.clone()
        }
    }

    #[tokio::test]
    async fn test_service_registration() {
        let manager = ServiceManager::new();
        let service = Arc::new(TestService::new("test1", Duration::from_millis(0)));

        // Test successful registration
        assert!(manager.register_service(service.clone()).await.is_ok());

        // Test duplicate registration
        assert!(manager.register_service(service).await.is_err());
    }

    #[tokio::test]
    async fn test_service_startup() {
        let manager = ServiceManager::new();
        let service = Arc::new(TestService::new("test1", Duration::from_millis(0)));

        assert!(manager.register_service(service).await.is_ok());
        assert!(manager.start_all().await.is_ok());

        // Give it a moment to start
        sleep(Duration::from_millis(100)).await;

        // Verify handle was created
        let handles = manager.handles.lock().await;
        assert!(handles.contains_key("test1"));
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let manager = ServiceManager::new();
        let service = Arc::new(TestService::new("test1", Duration::from_millis(100)));

        assert!(manager.register_service(service.clone()).await.is_ok());
        assert!(manager.start_all().await.is_ok());

        // Shutdown and verify it was graceful
        assert!(manager.shutdown_all().await.is_ok());
        assert!(service.was_shutdown());
    }

    #[tokio::test]
    async fn test_forced_shutdown() {
        let manager = ServiceManager::new();
        // Create a service with a shutdown delay longer than the timeout
        let service = Arc::new(TestService::new("test1", Duration::from_secs(20)));

        assert!(manager.register_service(service.clone()).await.is_ok());
        assert!(manager.start_all().await.is_ok());

        // Start timing the shutdown
        let start = std::time::Instant::now();
        assert!(manager.shutdown_all().await.is_ok());
        let duration = start.elapsed();

        // Verify that shutdown was forced (took less than 20 seconds)
        assert!(duration < Duration::from_secs(20));
    }

    #[tokio::test]
    async fn test_shutdown_signal() {
        let manager = ServiceManager::new();
        let mut rx = manager.get_shutdown_signal().await;

        // Send shutdown signal
        let _ = manager.shutdown_tx.send(());

        // Verify signal was received
        assert!(rx.recv().await.is_ok());
    }

    #[tokio::test]
    async fn test_multiple_services() {
        let manager = ServiceManager::new();
        let service1 = Arc::new(TestService::new("test1", Duration::from_millis(0)));
        let service2 = Arc::new(TestService::new("test2", Duration::from_millis(0)));

        // Register and start both services
        assert!(manager.register_service(service1.clone()).await.is_ok());
        assert!(manager.register_service(service2.clone()).await.is_ok());
        assert!(manager.start_all().await.is_ok());

        // Shutdown and verify both services were shutdown
        assert!(manager.shutdown_all().await.is_ok());
        assert!(service1.was_shutdown());
        assert!(service2.was_shutdown());
    }
}
