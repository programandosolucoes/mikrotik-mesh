use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRoute {
    pub tunnel_id: u16,
    pub peer_name: String,
    pub observed_endpoint: Option<SocketAddr>,
    pub is_relay_active: bool,
    pub allowed_macs: Vec<String>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Default)]
pub struct VpnRouter {
    routes: Arc<RwLock<HashMap<u16, TunnelRoute>>>,
}

impl VpnRouter {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_or_update_route(
        &self,
        tunnel_id: u16,
        peer_name: &str,
        endpoint: Option<SocketAddr>,
        is_relay: bool,
    ) {
        let mut routes = self.routes.write().await;
        let existing_macs = routes.get(&tunnel_id).map(|r| r.allowed_macs.clone()).unwrap_or_default();
        routes.insert(
            tunnel_id,
            TunnelRoute {
                tunnel_id,
                peer_name: peer_name.to_string(),
                observed_endpoint: endpoint,
                is_relay_active: is_relay,
                allowed_macs: existing_macs,
                tx_bytes: 0,
                rx_bytes: 0,
            },
        );
        info!(
            "VpnRouter: registered tunnel #{} for peer '{}' (endpoint: {:?}, relay: {})",
            tunnel_id, peer_name, endpoint, is_relay
        );
    }

    pub async fn set_mac_filter(&self, tunnel_id: u16, allowed_macs: Vec<String>) -> Result<()> {
        let mut routes = self.routes.write().await;
        if let Some(route) = routes.get_mut(&tunnel_id) {
            route.allowed_macs = allowed_macs;
            info!("VpnRouter: updated allowed MAC filter for tunnel #{}", tunnel_id);
            Ok(())
        } else {
            Err(anyhow!("Tunnel #{} not found", tunnel_id))
        }
    }

    pub async fn get_route(&self, tunnel_id: u16) -> Option<TunnelRoute> {
        let routes = self.routes.read().await;
        routes.get(&tunnel_id).cloned()
    }

    pub async fn list_routes(&self) -> Vec<TunnelRoute> {
        let routes = self.routes.read().await;
        routes.values().cloned().collect()
    }

    pub async fn remove_route(&self, tunnel_id: u16) -> Result<()> {
        let mut routes = self.routes.write().await;
        if routes.remove(&tunnel_id).is_some() {
            info!("VpnRouter: removed tunnel #{}", tunnel_id);
            Ok(())
        } else {
            Err(anyhow!("Tunnel #{} not found", tunnel_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vpn_router_operations() {
        let router = VpnRouter::new();
        router.register_or_update_route(101, "MikroTik-HQ", None, true).await;

        router
            .set_mac_filter(101, vec!["00:D9:D1:11:22:33".to_string()])
            .await
            .unwrap();

        let route = router.get_route(101).await.expect("Route must exist");
        assert_eq!(route.peer_name, "MikroTik-HQ");
        assert!(route.is_relay_active);
        assert_eq!(route.allowed_macs, vec!["00:D9:D1:11:22:33"]);

        let list = router.list_routes().await;
        assert_eq!(list.len(), 1);

        router.remove_route(101).await.unwrap();
        assert!(router.get_route(101).await.is_none());
    }
}
