use anyhow::{anyhow, Result};
use mkt_crypto::TunnelCipher;
use mkt_net::{
    create_tap_device, GreSocket, HttpsFramedMessage, HttpsRelayClient, TapDevice, TapWriter,
    PROTO_TYPE_EOIP, PROTO_TYPE_EOIP_ENCRYPTED,
};
use mkt_proto::{EoipPacket, EthernetFrame, MacAddr};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EoipTunnelConfig {
    pub tunnel_id: u16,
    pub local_addr: String,
    pub remote_addr: String,
    pub tap_name: String,
    pub use_https_relay: bool,
    pub ipsec_secret: Option<String>,
    #[serde(default)]
    pub allowed_macs: Vec<MacAddr>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TunnelStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub dropped_packets: u64,
    pub filtered_mac_packets: u64,
}

pub struct EoipTunnel {
    pub config: EoipTunnelConfig,
    pub tap: Arc<Mutex<Box<dyn TapDevice>>>,
    pub tap_writer: Arc<Mutex<Box<dyn TapWriter>>>,
    pub cipher: Option<Arc<TunnelCipher>>,
    pub allowed_macs: Arc<RwLock<Vec<MacAddr>>>,
    tx_packets: Arc<AtomicU64>,
    rx_packets: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
    dropped_packets: Arc<AtomicU64>,
    filtered_mac_packets: Arc<AtomicU64>,
}

impl EoipTunnel {
    pub fn with_tap(config: EoipTunnelConfig, tap: Box<dyn TapDevice>) -> Result<Self> {
        let tap_writer = tap.clone_writer()?;
        let macs = config.allowed_macs.clone();
        let cipher = config
            .ipsec_secret
            .as_ref()
            .map(|secret| Arc::new(TunnelCipher::from_secret(secret)));

        Ok(Self {
            config,
            tap: Arc::new(Mutex::new(tap)),
            tap_writer: Arc::new(Mutex::new(tap_writer)),
            cipher,
            allowed_macs: Arc::new(RwLock::new(macs)),
            tx_packets: Arc::new(AtomicU64::new(0)),
            rx_packets: Arc::new(AtomicU64::new(0)),
            tx_bytes: Arc::new(AtomicU64::new(0)),
            rx_bytes: Arc::new(AtomicU64::new(0)),
            dropped_packets: Arc::new(AtomicU64::new(0)),
            filtered_mac_packets: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn new(config: EoipTunnelConfig) -> Result<Self> {
        let tap = create_tap_device(&config.tap_name)?;
        Self::with_tap(config, tap)
    }

    pub async fn set_allowed_macs(&self, macs: Vec<MacAddr>) {
        let mut list = self.allowed_macs.write().await;
        *list = macs;
    }

    pub async fn is_frame_allowed(&self, frame_bytes: &[u8]) -> bool {
        let filter = self.allowed_macs.read().await;
        if filter.is_empty() {
            return true; // No filter configured: allow all
        }

        if let Ok(eth) = EthernetFrame::parse(frame_bytes) {
            // Check if source or destination is in allowlist
            let src_match = filter.contains(&eth.src_mac);
            let dst_match = filter.contains(&eth.dst_mac);

            if src_match || dst_match {
                return true;
            }

            // If it is a broadcast frame (e.g. ARP), only allow if originating from an allowed MAC
            if eth.dst_mac.is_broadcast() && src_match {
                return true;
            }
        }

        false
    }

    pub fn get_stats(&self) -> TunnelStats {
        TunnelStats {
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            filtered_mac_packets: self.filtered_mac_packets.load(Ordering::Relaxed),
        }
    }

    /// Automatically starts either HTTPS relay or native GRE loop based on configuration
    pub async fn start(self: Arc<Self>) -> Result<()> {
        if self.config.use_https_relay {
            self.start_https_relay_loop().await
        } else {
            self.start_gre_loop().await
        }
    }

    /// Full-duplex bidirectional HTTPS TCP 443 relay loop (Inbound: Relay -> TAP, Outbound: TAP -> Relay)
    pub async fn start_https_relay_loop(self: Arc<Self>) -> Result<()> {
        let remote = self.config.remote_addr.clone();
        let tunnel_id = self.config.tunnel_id;

        info!(
            "Starting EoIP Tunnel #{} over HTTPS TCP 443 Relay to {}",
            tunnel_id, remote
        );

        let (mut read_client, mut write_client) = HttpsRelayClient::connect_split(&remote).await?;

        // Send initial keepalive frame to register peer immediately in RelayHub
        let keepalive = EoipPacket::keepalive(tunnel_id);
        let mut wire = vec![0u8; 8];
        if let Ok(w) = keepalive.serialize(&mut wire) {
            let mut msg = HttpsFramedMessage::new(
                PROTO_TYPE_EOIP,
                tunnel_id,
                wire[..w].to_vec(),
            );
            if let Some(ref cipher) = self.cipher {
                let _ = msg.encrypt(cipher);
            }
            if let Err(e) = write_client.send_message(&msg).await {
                warn!("Tunnel #{}: Failed to send initial keepalive registration: {}", tunnel_id, e);
            }
        }

        // 1. Inbound Task: Relay Network -> TAP interface
        let tap_writer = self.tap_writer.clone();
        let rx_pkts = self.rx_packets.clone();
        let rx_bts = self.rx_bytes.clone();
        let dropped_rx = self.dropped_packets.clone();
        let filtered_rx = self.filtered_mac_packets.clone();
        let self_clone_rx = self.clone();
        let cipher_rx = self.cipher.clone();

        tokio::spawn(async move {
            loop {
                match read_client.recv_frame().await {
                    Ok(mut frame) => {
                        if frame.tunnel_id != tunnel_id {
                            continue;
                        }

                        // Authenticated decryption if payload is encrypted or cipher configured
                        if let Some(ref cipher) = cipher_rx {
                            if frame.proto_type == PROTO_TYPE_EOIP_ENCRYPTED {
                                if let Err(e) = frame.decrypt(cipher) {
                                    warn!("Tunnel #{}: Failed to decrypt AEAD frame: {}", tunnel_id, e);
                                    dropped_rx.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                            } else if frame.proto_type == PROTO_TYPE_EOIP {
                                warn!("Tunnel #{}: Rejected unencrypted frame on encrypted tunnel", tunnel_id);
                                dropped_rx.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        }

                        if frame.proto_type != PROTO_TYPE_EOIP {
                            continue;
                        }

                        match EoipPacket::parse(&frame.payload) {
                            Ok(packet) => {
                                if packet.header.is_keepalive() {
                                    continue;
                                }

                                // Apply MAC Address allowlist filter
                                if !self_clone_rx.is_frame_allowed(&packet.ethernet_frame_raw).await {
                                    filtered_rx.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }

                                let mut writer = tap_writer.lock().await;
                                if let Err(e) = writer.write_frame(&packet.ethernet_frame_raw).await {
                                    warn!("Error injecting frame into TAP: {}", e);
                                    dropped_rx.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    rx_pkts.fetch_add(1, Ordering::Relaxed);
                                    rx_bts.fetch_add(packet.ethernet_frame_raw.len() as u64, Ordering::Relaxed);
                                }
                            }
                            Err(e) => {
                                warn!("Malformed EoIP packet received: {}", e);
                                dropped_rx.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Relay stream connection error: {}. Waiting to retry...", e);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        });

        // 2. Outbound Task: TAP interface -> Relay Network
        let tap_reader = self.tap.clone();
        let tx_pkts = self.tx_packets.clone();
        let tx_bts = self.tx_bytes.clone();
        let dropped_tx = self.dropped_packets.clone();
        let filtered_tx = self.filtered_mac_packets.clone();
        let self_clone_tx = self.clone();
        let cipher_tx = self.cipher.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let len = {
                    let mut tap = tap_reader.lock().await;
                    match tap.read_frame(&mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            warn!("Tunnel #{}: TAP read error: {}", tunnel_id, e);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    }
                };

                let frame = &buf[..len];

                // Apply MAC Address allowlist filter
                if !self_clone_tx.is_frame_allowed(frame).await {
                    filtered_tx.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // Wrap Ethernet frame in standard EoIP packet
                let eoip_pkt = match EoipPacket::new(tunnel_id, frame.to_vec()) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Tunnel #{}: Failed to construct EoIP packet: {}", tunnel_id, e);
                        dropped_tx.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                let mut wire = vec![0u8; 8 + frame.len()];
                let written = match eoip_pkt.serialize(&mut wire) {
                    Ok(w) => w,
                    Err(e) => {
                        warn!("Tunnel #{}: Serialization error: {}", tunnel_id, e);
                        dropped_tx.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                let mut msg = HttpsFramedMessage::new(
                    PROTO_TYPE_EOIP,
                    tunnel_id,
                    wire[..written].to_vec(),
                );

                // Authenticated encryption if cipher configured
                if let Some(ref cipher) = cipher_tx {
                    if let Err(e) = msg.encrypt(cipher) {
                        warn!("Tunnel #{}: Failed to encrypt frame: {}", tunnel_id, e);
                        dropped_tx.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }

                if let Err(e) = write_client.send_message(&msg).await {
                    warn!("Tunnel #{}: Error forwarding frame to relay: {}", tunnel_id, e);
                    dropped_tx.fetch_add(1, Ordering::Relaxed);
                } else {
                    tx_pkts.fetch_add(1, Ordering::Relaxed);
                    tx_bts.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }
            }
        });

        Ok(())
    }

    /// Full-duplex bidirectional native GRE loop (IP Protocol 47 / AF_INET SOCK_RAW)
    /// Direct communication with MikroTik RouterOS devices without relay
    pub async fn start_gre_loop(self: Arc<Self>) -> Result<()> {
        let tunnel_id = self.config.tunnel_id;
        let local_ip: Ipv4Addr = self
            .config
            .local_addr
            .parse()
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        let remote_ip: Ipv4Addr = self
            .config
            .remote_addr
            .split(':')
            .next()
            .unwrap_or(&self.config.remote_addr)
            .parse()
            .map_err(|e| anyhow!("Invalid remote IPv4 address for native GRE: {}", e))?;

        info!(
            "Starting native GRE EoIP Tunnel #{} to remote MikroTik {} (local: {})...",
            tunnel_id, remote_ip, local_ip
        );

        let gre = GreSocket::bind(local_ip, remote_ip)?;
        let is_raw = gre.is_raw();
        let (mut gre_rx, gre_tx) = gre.split();

        if is_raw {
            info!("Native GRE socket running on raw IP protocol 47 (SOCK_RAW)");
        } else {
            info!("Native GRE socket operating in portable fallback mode");
        }

        // 1. Inbound Task: GRE Network -> TAP interface
        let tap_writer = self.tap_writer.clone();
        let rx_pkts = self.rx_packets.clone();
        let rx_bts = self.rx_bytes.clone();
        let dropped_rx = self.dropped_packets.clone();
        let filtered_rx = self.filtered_mac_packets.clone();
        let self_clone_rx = self.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                match gre_rx.recv_packet(&mut buf).await {
                    Ok(len) => {
                        match EoipPacket::parse(&buf[..len]) {
                            Ok(packet) => {
                                if packet.header.tunnel_id != tunnel_id {
                                    continue;
                                }

                                if packet.header.is_keepalive() {
                                    continue;
                                }

                                // Apply MAC Address allowlist filter
                                if !self_clone_rx.is_frame_allowed(&packet.ethernet_frame_raw).await {
                                    filtered_rx.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }

                                let mut writer = tap_writer.lock().await;
                                if let Err(e) = writer.write_frame(&packet.ethernet_frame_raw).await {
                                    warn!("Error injecting GRE frame into TAP: {}", e);
                                    dropped_rx.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    rx_pkts.fetch_add(1, Ordering::Relaxed);
                                    rx_bts.fetch_add(packet.ethernet_frame_raw.len() as u64, Ordering::Relaxed);
                                }
                            }
                            Err(e) => {
                                warn!("Malformed GRE EoIP packet received: {}", e);
                                dropped_rx.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(e) => {
                        error!("GRE receive error: {}. Ending inbound loop.", e);
                        break;
                    }
                }
            }
        });

        // 2. Outbound Task: TAP interface -> GRE Network
        let tap_reader = self.tap.clone();
        let tx_pkts = self.tx_packets.clone();
        let tx_bts = self.tx_bytes.clone();
        let dropped_tx = self.dropped_packets.clone();
        let filtered_tx = self.filtered_mac_packets.clone();
        let self_clone_tx = self.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let len = {
                    let mut tap = tap_reader.lock().await;
                    match tap.read_frame(&mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            warn!("Tunnel #{}: TAP read error: {}", tunnel_id, e);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    }
                };

                let frame = &buf[..len];

                // Apply MAC Address allowlist filter
                if !self_clone_tx.is_frame_allowed(frame).await {
                    filtered_tx.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // Wrap Ethernet frame in standard EoIP packet
                let eoip_pkt = match EoipPacket::new(tunnel_id, frame.to_vec()) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Tunnel #{}: Failed to construct EoIP packet: {}", tunnel_id, e);
                        dropped_tx.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                let mut wire = vec![0u8; 8 + frame.len()];
                let written = match eoip_pkt.serialize(&mut wire) {
                    Ok(w) => w,
                    Err(e) => {
                        warn!("Tunnel #{}: Serialization error: {}", tunnel_id, e);
                        dropped_tx.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                if let Err(e) = gre_tx.send_packet(&wire[..written]).await {
                    warn!("Tunnel #{}: Failed to send GRE packet: {}", tunnel_id, e);
                    dropped_tx.fetch_add(1, Ordering::Relaxed);
                } else {
                    tx_pkts.fetch_add(1, Ordering::Relaxed);
                    tx_bts.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkt_net::{HttpsRelayServer, RelayHub};

    #[tokio::test]
    async fn test_mac_filter_enforcement() {
        let ps5_mac = MacAddr([0x00, 0xD9, 0xD1, 0x11, 0x22, 0x33]);
        let pc_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let other_mac = MacAddr([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

        let config = EoipTunnelConfig {
            tunnel_id: 100,
            local_addr: "0.0.0.0".to_string(),
            remote_addr: "127.0.0.1:443".to_string(),
            tap_name: "test-tap1".to_string(),
            use_https_relay: true,
            ipsec_secret: None,
            allowed_macs: vec![ps5_mac],
        };

        let tunnel = EoipTunnel::new(config).unwrap();

        // Frame from PC to PS5 -> Allowed
        let frame_to_ps5 = EthernetFrame {
            dst_mac: ps5_mac,
            src_mac: pc_mac,
            ethertype: 0x0800,
            payload: vec![1, 2, 3],
        };
        let mut buf1 = vec![0u8; 32];
        let len1 = frame_to_ps5.serialize(&mut buf1).unwrap();
        assert!(tunnel.is_frame_allowed(&buf1[..len1]).await);

        // Frame from other device to other device -> Blocked
        let frame_unrelated = EthernetFrame {
            dst_mac: other_mac,
            src_mac: pc_mac,
            ethertype: 0x0800,
            payload: vec![1, 2, 3],
        };
        let mut buf2 = vec![0u8; 32];
        let len2 = frame_unrelated.serialize(&mut buf2).unwrap();
        assert!(!tunnel.is_frame_allowed(&buf2[..len2]).await);
    }

    #[tokio::test]
    async fn test_gre_loop_initialization() {
        let config = EoipTunnelConfig {
            tunnel_id: 200,
            local_addr: "127.0.0.1".to_string(),
            remote_addr: "127.0.0.1".to_string(),
            tap_name: "test-gre-tap".to_string(),
            use_https_relay: false,
            ipsec_secret: None,
            allowed_macs: Vec::new(),
        };

        let tunnel = Arc::new(EoipTunnel::new(config).unwrap());
        // Verify start_gre_loop succeeds (either raw socket or fallback abstraction)
        assert!(tunnel.start_gre_loop().await.is_ok());
    }

    #[tokio::test]
    async fn test_bidirectional_relay_with_encryption() {
        // Start relay hub server on ephemeral port
        let server = Arc::new(HttpsRelayServer::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.listener.local_addr().unwrap();
        let hub = Arc::new(RelayHub::new());
        let hub_clone = hub.clone();
        let server_clone = server.clone();

        tokio::spawn(async move {
            let _ = server_clone.run_hub(hub_clone).await;
        });

        let shared_secret = "UltraSecretMeshKey2026!";

        // Endpoint 1
        let config1 = EoipTunnelConfig {
            tunnel_id: 777,
            local_addr: "0.0.0.0".to_string(),
            remote_addr: server_addr.to_string(),
            tap_name: "tap-side1".to_string(),
            use_https_relay: true,
            ipsec_secret: Some(shared_secret.to_string()),
            allowed_macs: Vec::new(),
        };
        let tunnel1 = Arc::new(EoipTunnel::new(config1).unwrap());
        tunnel1.clone().start_https_relay_loop().await.unwrap();

        // Endpoint 2
        let config2 = EoipTunnelConfig {
            tunnel_id: 777,
            local_addr: "0.0.0.0".to_string(),
            remote_addr: server_addr.to_string(),
            tap_name: "tap-side2".to_string(),
            use_https_relay: true,
            ipsec_secret: Some(shared_secret.to_string()),
            allowed_macs: Vec::new(),
        };
        let tunnel2 = Arc::new(EoipTunnel::new(config2).unwrap());
        tunnel2.clone().start_https_relay_loop().await.unwrap();

        // Allow connection and registration in hub
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Inject frame into TAP 1 writer
        let test_frame = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x08, 0x00, 0xCA, 0xFE];
        {
            let mut writer1 = tunnel1.tap_writer.lock().await;
            writer1.write_frame(&test_frame).await.unwrap();
        }

        // Wait brief moment for relay and verification
        tokio::time::sleep(Duration::from_millis(150)).await;
        let stats1 = tunnel1.get_stats();
        assert_eq!(stats1.dropped_packets, 0);
    }
}
