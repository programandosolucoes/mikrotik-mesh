use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use mkt_crypto::TunnelCipher;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

pub const FRAME_MAGIC: u16 = 0x4D4B; // "MK" in ASCII
pub const PROTO_TYPE_EOIP: u8 = 0x01;
pub const PROTO_TYPE_MACTELNET: u8 = 0x02;
pub const PROTO_TYPE_STUN_SIGNAL: u8 = 0x03;
pub const PROTO_TYPE_EOIP_ENCRYPTED: u8 = 0x11; // ChaCha20-Poly1305 encrypted EoIP payload

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsFramedMessage {
    pub proto_type: u8,
    pub tunnel_id: u16,
    pub payload: Vec<u8>,
}

impl HttpsFramedMessage {
    pub fn new(proto_type: u8, tunnel_id: u16, payload: Vec<u8>) -> Self {
        Self {
            proto_type,
            tunnel_id,
            payload,
        }
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize> {
        let total = 7 + self.payload.len();
        if buf.len() < total {
            return Err(anyhow!("Buffer too small for framed message"));
        }

        BigEndian::write_u16(&mut buf[0..2], FRAME_MAGIC);
        buf[2] = self.proto_type;
        BigEndian::write_u16(&mut buf[3..5], self.tunnel_id);
        BigEndian::write_u16(&mut buf[5..7], self.payload.len() as u16);
        buf[7..total].copy_from_slice(&self.payload);

        Ok(total)
    }

    pub async fn read_from_stream<T: AsyncReadExt + Unpin>(stream: &mut T) -> Result<Self> {
        let mut header = [0u8; 7];
        stream.read_exact(&mut header).await?;

        let magic = BigEndian::read_u16(&header[0..2]);
        if magic != FRAME_MAGIC {
            return Err(anyhow!("Invalid framed stream magic: 0x{:04x}", magic));
        }

        let proto_type = header[2];
        let tunnel_id = BigEndian::read_u16(&header[3..5]);
        let payload_len = BigEndian::read_u16(&header[5..7]) as usize;

        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await?;

        Ok(Self {
            proto_type,
            tunnel_id,
            payload,
        })
    }

    pub async fn write_to_stream<T: AsyncWriteExt + Unpin>(&self, stream: &mut T) -> Result<()> {
        let mut buf = vec![0u8; 7 + self.payload.len()];
        let written = self.serialize(&mut buf)?;
        stream.write_all(&buf[..written]).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Encrypts payload with ChaCha20-Poly1305 and sets proto_type to PROTO_TYPE_EOIP_ENCRYPTED
    pub fn encrypt(&mut self, cipher: &TunnelCipher) -> Result<()> {
        let encrypted = cipher
            .encrypt(&self.payload)
            .map_err(|e| anyhow!("Encryption error: {}", e))?;
        self.payload = encrypted;
        self.proto_type = PROTO_TYPE_EOIP_ENCRYPTED;
        Ok(())
    }

    /// Decrypts payload with ChaCha20-Poly1305 if encrypted and resets proto_type to PROTO_TYPE_EOIP
    pub fn decrypt(&mut self, cipher: &TunnelCipher) -> Result<()> {
        if self.proto_type == PROTO_TYPE_EOIP_ENCRYPTED {
            let decrypted = cipher
                .decrypt(&self.payload)
                .map_err(|e| anyhow!("Decryption error: {}", e))?;
            self.payload = decrypted;
            self.proto_type = PROTO_TYPE_EOIP;
        }
        Ok(())
    }
}

/// Multiplexing Relay Hub that routes frames bidirectionally between connected peers sharing the same tunnel_id
pub struct RelayHub {
    // Map of tunnel_id -> (client_id -> Sender)
    tunnels: Arc<RwLock<HashMap<u16, HashMap<u64, mpsc::Sender<HttpsFramedMessage>>>>>,
    // Map of client_id -> set of registered tunnel_ids
    client_tunnels: Arc<RwLock<HashMap<u64, HashSet<u16>>>>,
    next_client_id: Arc<AtomicU64>,
}

impl Default for RelayHub {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayHub {
    pub fn new() -> Self {
        Self {
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            client_tunnels: Arc::new(RwLock::new(HashMap::new())),
            next_client_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Registers and manages a newly accepted TCP connection on the relay hub
    pub async fn handle_connection(self: Arc<Self>, stream: TcpStream, peer_addr: SocketAddr) {
        let client_id = self.next_client_id.fetch_add(1, Ordering::Relaxed);
        info!("RelayHub: accepted peer #{}: {}", client_id, peer_addr);

        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<HttpsFramedMessage>(512);

        // Task: Write outgoing frames from other peers to this TCP connection
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = msg.write_to_stream(&mut writer).await {
                    debug!("RelayHub: write error to peer #{}: {}", client_id, e);
                    break;
                }
            }
        });

        // Loop: Read incoming frames from this TCP connection and broadcast to peers
        let hub = self.clone();
        tokio::spawn(async move {
            loop {
                match HttpsFramedMessage::read_from_stream(&mut reader).await {
                    Ok(msg) => {
                        hub.register_and_broadcast(client_id, tx.clone(), msg).await;
                    }
                    Err(e) => {
                        debug!("RelayHub: peer #{} disconnected: {}", client_id, e);
                        break;
                    }
                }
            }
            hub.remove_client(client_id).await;
            info!("RelayHub: peer #{} cleaned up", client_id);
        });
    }

    /// Associates client with tunnel_id and broadcasts frame to all other peers in that tunnel
    async fn register_and_broadcast(
        &self,
        sender_id: u64,
        sender_tx: mpsc::Sender<HttpsFramedMessage>,
        msg: HttpsFramedMessage,
    ) {
        let tunnel_id = msg.tunnel_id;

        // Register client in tunnel mapping
        {
            let mut tunnels = self.tunnels.write().await;
            let peers = tunnels.entry(tunnel_id).or_default();
            peers.entry(sender_id).or_insert(sender_tx);
        }

        {
            let mut client_tunnels = self.client_tunnels.write().await;
            let t_set = client_tunnels.entry(sender_id).or_default();
            t_set.insert(tunnel_id);
        }

        // Broadcast to all other peers subscribed to this tunnel_id
        let targets: Vec<(u64, mpsc::Sender<HttpsFramedMessage>)> = {
            let tunnels = self.tunnels.read().await;
            if let Some(peers) = tunnels.get(&tunnel_id) {
                peers
                    .iter()
                    .filter(|(id, _)| **id != sender_id)
                    .map(|(id, tx)| (*id, tx.clone()))
                    .collect()
            } else {
                Vec::new()
            }
        };

        let mut dead_clients = Vec::new();
        for (peer_id, tx) in targets {
            match tx.try_send(msg.clone()) {
                Ok(_) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!("RelayHub: buffer full for peer #{}, dropping frame", peer_id);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    dead_clients.push(peer_id);
                }
            }
        }

        if !dead_clients.is_empty() {
            let mut tunnels = self.tunnels.write().await;
            if let Some(peers) = tunnels.get_mut(&tunnel_id) {
                for dead_id in dead_clients {
                    peers.remove(&dead_id);
                }
            }
        }
    }

    /// Removes a client from all tunnel registrations
    pub async fn remove_client(&self, client_id: u64) {
        let registered_tunnels = {
            let mut client_tunnels = self.client_tunnels.write().await;
            client_tunnels.remove(&client_id).unwrap_or_default()
        };

        let mut tunnels = self.tunnels.write().await;
        for tunnel_id in registered_tunnels {
            if let Some(peers) = tunnels.get_mut(&tunnel_id) {
                peers.remove(&client_id);
                if peers.is_empty() {
                    tunnels.remove(&tunnel_id);
                }
            }
        }
    }

    pub async fn active_tunnels_count(&self) -> usize {
        self.tunnels.read().await.len()
    }

    pub async fn active_peers_for_tunnel(&self, tunnel_id: u16) -> usize {
        self.tunnels
            .read()
            .await
            .get(&tunnel_id)
            .map(|m| m.len())
            .unwrap_or(0)
    }
}

/// UDP Socket abstraction for MAC-Telnet (port 20561) and standard L2 UDP relay
pub struct UdpMeshSocket {
    pub socket: UdpSocket,
}

impl UdpMeshSocket {
    pub async fn bind(addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        socket.set_broadcast(true)?;
        info!("UdpMeshSocket bound to {}", addr);
        Ok(Self { socket })
    }

    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        Ok(self.socket.send_to(buf, target).await?)
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Ok(self.socket.recv_from(buf).await?)
    }
}

/// TCP 443 / HTTPS Relay Server (Accepts connections from behind NAT/firewalls and XAMPP/Hostinger)
pub struct HttpsRelayServer {
    pub listener: TcpListener,
}

impl HttpsRelayServer {
    pub async fn bind(bind_addr: &str) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("HttpsRelayServer listening on TCP {}", bind_addr);
        Ok(Self { listener })
    }

    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr)> {
        Ok(self.listener.accept().await?)
    }

    /// Runs the relay hub loop indefinitely, routing traffic between clients
    pub async fn run_hub(self: Arc<Self>, hub: Arc<RelayHub>) -> Result<()> {
        loop {
            let (stream, peer_addr) = self.accept().await?;
            let hub_clone = hub.clone();
            tokio::spawn(async move {
                hub_clone.handle_connection(stream, peer_addr).await;
            });
        }
    }
}

/// Split reader half for HttpsRelayClient
pub struct HttpsRelayReader {
    reader: OwnedReadHalf,
}

impl HttpsRelayReader {
    pub async fn recv_frame(&mut self) -> Result<HttpsFramedMessage> {
        HttpsFramedMessage::read_from_stream(&mut self.reader).await
    }
}

/// Split writer half for HttpsRelayClient
pub struct HttpsRelayWriter {
    writer: OwnedWriteHalf,
}

impl HttpsRelayWriter {
    pub async fn send_frame(&mut self, proto_type: u8, tunnel_id: u16, payload: &[u8]) -> Result<()> {
        let msg = HttpsFramedMessage::new(proto_type, tunnel_id, payload.to_vec());
        msg.write_to_stream(&mut self.writer).await
    }

    pub async fn send_message(&mut self, msg: &HttpsFramedMessage) -> Result<()> {
        msg.write_to_stream(&mut self.writer).await
    }
}

/// TCP 443 / HTTPS Relay Client (Connects from edge MikroTik or Linux/Windows host to central VPS/XAMPP)
pub struct HttpsRelayClient {
    pub target_addr: String,
    pub stream: Option<TcpStream>,
}

impl HttpsRelayClient {
    pub fn new(target_addr: &str) -> Self {
        Self {
            target_addr: target_addr.to_string(),
            stream: None,
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to central HTTPS relay at {}...", self.target_addr);
        let stream = TcpStream::connect(&self.target_addr).await?;
        self.stream = Some(stream);
        info!("Connected to central HTTPS relay successfully!");
        Ok(())
    }

    /// Connect and return independent reader and writer handles for non-blocking full duplex traffic
    pub async fn connect_split(target_addr: &str) -> Result<(HttpsRelayReader, HttpsRelayWriter)> {
        info!("Connecting to central HTTPS relay at {} (split mode)...", target_addr);
        let stream = TcpStream::connect(target_addr).await?;
        let (reader, writer) = stream.into_split();
        Ok((HttpsRelayReader { reader }, HttpsRelayWriter { writer }))
    }

    pub fn into_split(self) -> Result<(HttpsRelayReader, HttpsRelayWriter)> {
        let stream = self.stream.ok_or_else(|| anyhow!("Relay stream not connected"))?;
        let (reader, writer) = stream.into_split();
        Ok((HttpsRelayReader { reader }, HttpsRelayWriter { writer }))
    }

    pub async fn send_frame(&mut self, proto_type: u8, tunnel_id: u16, payload: &[u8]) -> Result<()> {
        if self.stream.is_none() {
            self.connect().await?;
        }

        if let Some(ref mut stream) = self.stream {
            let msg = HttpsFramedMessage::new(proto_type, tunnel_id, payload.to_vec());
            msg.write_to_stream(stream).await?;
            Ok(())
        } else {
            Err(anyhow!("Relay stream not connected"))
        }
    }

    pub async fn recv_frame(&mut self) -> Result<HttpsFramedMessage> {
        if self.stream.is_none() {
            self.connect().await?;
        }

        if let Some(ref mut stream) = self.stream {
            HttpsFramedMessage::read_from_stream(stream).await
        } else {
            Err(anyhow!("Relay stream not connected"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_https_framed_message_roundtrip() {
        let payload = vec![0x00, 0x0c, 0x42, 0xaa, 0xbb, 0xcc, 0x08, 0x00, 0xde, 0xad];
        let msg = HttpsFramedMessage::new(PROTO_TYPE_EOIP, 1001, payload.clone());

        let mut buffer = vec![0u8; 64];
        let written = msg.serialize(&mut buffer).unwrap();

        assert_eq!(written, 7 + payload.len());

        let mut cursor = std::io::Cursor::new(&buffer[..written]);
        let parsed = HttpsFramedMessage::read_from_stream(&mut cursor).await.unwrap();

        assert_eq!(parsed.proto_type, PROTO_TYPE_EOIP);
        assert_eq!(parsed.tunnel_id, 1001);
        assert_eq!(parsed.payload, payload);
    }

    #[tokio::test]
    async fn test_https_framed_message_encryption() {
        let cipher = TunnelCipher::from_secret("MeshRelayPresharedKey");
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let mut msg = HttpsFramedMessage::new(PROTO_TYPE_EOIP, 200, payload.clone());

        msg.encrypt(&cipher).unwrap();
        assert_eq!(msg.proto_type, PROTO_TYPE_EOIP_ENCRYPTED);
        assert_ne!(msg.payload, payload);

        msg.decrypt(&cipher).unwrap();
        assert_eq!(msg.proto_type, PROTO_TYPE_EOIP);
        assert_eq!(msg.payload, payload);
    }

    #[tokio::test]
    async fn test_relay_hub_multiplexing_between_peers() {
        let hub = Arc::new(RelayHub::new());

        // Spawn mock relay server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let hub_clone = hub.clone();
        tokio::spawn(async move {
            while let Ok((stream, addr)) = listener.accept().await {
                let h = hub_clone.clone();
                tokio::spawn(async move {
                    h.handle_connection(stream, addr).await;
                });
            }
        });

        // Client 1 connects to tunnel 555
        let (_r1, mut w1) = HttpsRelayClient::connect_split(&server_addr.to_string()).await.unwrap();
        // Client 2 connects to tunnel 555
        let (mut r2, mut w2) = HttpsRelayClient::connect_split(&server_addr.to_string()).await.unwrap();
        // Client 3 connects to different tunnel 999
        let (_r3, mut w3) = HttpsRelayClient::connect_split(&server_addr.to_string()).await.unwrap();

        // Client 1 sends a frame on tunnel 555 to register and transmit
        let data1 = vec![0xAA, 0xBB, 0xCC];
        w1.send_frame(PROTO_TYPE_EOIP, 555, &data1).await.unwrap();

        // Client 2 sends a dummy frame on tunnel 555 to register
        let data2 = vec![0x11, 0x22];
        w2.send_frame(PROTO_TYPE_EOIP, 555, &data2).await.unwrap();

        // Client 3 sends on tunnel 999
        w3.send_frame(PROTO_TYPE_EOIP, 999, &[0xFF]).await.unwrap();

        // Wait until both peers are registered in RelayHub for tunnel 555
        for _ in 0..50 {
            if hub.active_peers_for_tunnel(555).await >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Now Client 1 sends message destined for tunnel 555
        let test_payload = vec![0xCA, 0xFE, 0xBA, 0xBE];
        w1.send_frame(PROTO_TYPE_EOIP, 555, &test_payload).await.unwrap();


        // Client 2 should receive the message on tunnel 555
        let received = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            loop {
                let msg = r2.recv_frame().await.unwrap();
                if msg.payload == test_payload {
                    return msg;
                }
            }
        })
        .await
        .expect("Client 2 must receive message on tunnel 555");

        assert_eq!(received.tunnel_id, 555);
        assert_eq!(received.payload, test_payload);
    }
}
