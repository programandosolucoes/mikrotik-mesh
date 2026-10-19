use anyhow::{anyhow, Result};
use crate::router::VpnRouter;
use crate::tunnel::{EoipTunnel, EoipTunnelConfig};
use crate::wakeup::{send_ps5_wakeup_packet, send_wol_packet};
use mkt_proto::MacAddr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub const DEFAULT_CONTROL_PORT: u16 = 20560;

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub service: String,
    pub version: u32,
    pub uptime_secs: u64,
    pub active_tunnels_count: usize,
}

pub struct MeshDaemon {
    router: Arc<VpnRouter>,
    active_tunnels: Arc<RwLock<HashMap<u16, Arc<EoipTunnel>>>>,
    start_time: std::time::Instant,
}

impl MeshDaemon {
    pub fn new(router: Arc<VpnRouter>) -> Self {
        Self {
            router,
            active_tunnels: Arc::new(RwLock::new(HashMap::new())),
            start_time: std::time::Instant::now(),
        }
    }

    pub async fn add_tunnel(&self, config: EoipTunnelConfig) -> Result<()> {
        let tunnel_id = config.tunnel_id;
        let tunnel = Arc::new(EoipTunnel::new(config.clone())?);

        let t_clone = tunnel.clone();
        tokio::spawn(async move {
            if let Err(e) = t_clone.start().await {
                error!("Tunnel #{} data plane error: {}", tunnel_id, e);
            }
        });


        self.router
            .register_or_update_route(
                tunnel_id,
                &config.tap_name,
                config.remote_addr.parse().ok(),
                config.use_https_relay,
            )
            .await;

        let mut map = self.active_tunnels.write().await;
        map.insert(tunnel_id, tunnel);
        info!("MeshDaemon: tunnel #{} started and persistent in background", tunnel_id);
        Ok(())
    }

    pub async fn set_tunnel_mac_filter(&self, tunnel_id: u16, macs: Vec<MacAddr>) -> Result<()> {
        let map = self.active_tunnels.read().await;
        if let Some(t) = map.get(&tunnel_id) {
            t.set_allowed_macs(macs.clone()).await;
            let str_macs = macs.into_iter().map(|m| m.to_string()).collect();
            self.router.set_mac_filter(tunnel_id, str_macs).await?;
            Ok(())
        } else {
            Err(anyhow!("Tunnel #{} not running", tunnel_id))
        }
    }

    pub async fn remove_tunnel(&self, tunnel_id: u16) -> Result<()> {
        let mut map = self.active_tunnels.write().await;
        if map.remove(&tunnel_id).is_some() {
            self.router.remove_route(tunnel_id).await?;
            info!("MeshDaemon: tunnel #{} stopped", tunnel_id);
            Ok(())
        } else {
            Err(anyhow!("Tunnel #{} not found", tunnel_id))
        }
    }

    pub async fn run_control_api(self: Arc<Self>, bind_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("MeshDaemon Control API listening on http://{}", bind_addr);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let daemon = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = daemon.handle_http_client(stream).await {
                            warn!("Error handling control API request: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Control API listener error: {}", e);
                }
            }
        }
    }

    async fn handle_http_client(&self, mut stream: TcpStream) -> Result<()> {
        let mut buf = vec![0u8; 4096];
        let bytes_read = stream.read(&mut buf).await?;
        if bytes_read == 0 {
            return Ok(());
        }

        let req_text = String::from_utf8_lossy(&buf[..bytes_read]);
        let mut lines = req_text.lines();
        let first_line = lines.next().unwrap_or("");
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let path = parts.next().unwrap_or("/");

        let (status_code, body) = match (method, path) {
            ("GET", "/api/status") => {
                let tunnels_count = self.active_tunnels.read().await.len();
                let status = DaemonStatus {
                    service: "mikrotik-mesh-daemon".to_string(),
                    version: 1,
                    uptime_secs: self.start_time.elapsed().as_secs(),
                    active_tunnels_count: tunnels_count,
                };
                (200, serde_json::to_string(&status)?)
            }
            ("GET", "/api/tunnels") => {
                let routes = self.router.list_routes().await;
                (200, serde_json::to_string(&routes)?)
            }
            ("POST", "/api/wakeup/wol") => {
                // Parse body looking for mac
                let body_str = req_text.split("\r\n\r\n").nth(1).unwrap_or("");
                let json: serde_json::Value = serde_json::from_str(body_str).unwrap_or_default();
                let mac_str = json["mac"].as_str().unwrap_or("");
                let bcast = json["broadcast"].as_str().unwrap_or("255.255.255.255:9");

                if let Ok(mac) = mac_str.parse::<MacAddr>() {
                    let _ = send_wol_packet(&mac, bcast);
                    (200, r#"{"success":true,"message":"WoL sent"}"#.to_string())
                } else {
                    (400, r#"{"error":"Invalid MAC address"}"#.to_string())
                }
            }
            ("POST", "/api/wakeup/ps5") => {
                let body_str = req_text.split("\r\n\r\n").nth(1).unwrap_or("");
                let json: serde_json::Value = serde_json::from_str(body_str).unwrap_or_default();
                let ip_str = json["ip"].as_str().unwrap_or("");
                let cred = json["credential"].as_str();

                if !ip_str.is_empty() {
                    let _ = send_ps5_wakeup_packet(ip_str, cred);
                    (200, r#"{"success":true,"message":"PS5 wakeup sent"}"#.to_string())
                } else {
                    (400, r#"{"error":"Missing PS5 IP address"}"#.to_string())
                }
            }
            ("GET", "/api/wakeup/ps5/discover") => {
                let devices = crate::wakeup::discover_ps5_devices(1000).unwrap_or_default();
                let result: Vec<serde_json::Value> = devices
                    .into_iter()
                    .map(|(ip, name)| serde_json::json!({ "ip": ip, "host_name": name }))
                    .collect();
                (200, serde_json::to_string(&result)?)
            }
            _ => (404, r#"{"error":"Not Found"}"#.to_string()),
        };

        let response = format!(
            "HTTP/1.1 {} OK\r\n\
             Content-Type: application/json\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            status_code,
            body.len(),
            body
        );

        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
        Ok(())
    }
}
