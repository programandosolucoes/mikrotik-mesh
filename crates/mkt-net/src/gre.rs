use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub const IPPROTO_GRE: i32 = 47;

enum GreBackend {
    Raw {
        socket: Arc<socket2::Socket>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
    Fallback {
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Vec<u8>>,
    },
}

/// Native GRE (IP Protocol 47 / AF_INET SOCK_RAW) socket abstraction.
/// Handles raw IP encapsulation for MikroTik EoIP on Linux and Windows (with Administrator),
/// providing a safe fallback on restricted OS environments.
pub struct GreSocket {
    backend: GreBackend,
    local_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    is_raw: bool,
}

impl GreSocket {
    /// Bind a native GRE socket to talk with a remote IP
    pub fn bind(local_addr: Ipv4Addr, remote_addr: Ipv4Addr) -> Result<Self> {
        info!(
            "Attempting to bind native GRE socket (IP Proto 47) local: {}, remote: {}",
            local_addr, remote_addr
        );

        match Self::try_create_raw_socket(local_addr, remote_addr) {
            Ok((socket, rx)) => {
                info!(
                    "Native GRE socket (IP Proto 47 SOCK_RAW) bound successfully (local: {}, remote: {})",
                    local_addr, remote_addr
                );
                Ok(Self {
                    backend: GreBackend::Raw { socket, rx },
                    local_addr,
                    remote_addr,
                    is_raw: true,
                })
            }
            Err(e) => {
                warn!(
                    "Raw GRE socket (IP Proto 47) unavailable on this system/user privilege: {}. \
                     Activating clean fallback socket abstraction. \
                     Note: On Windows without Administrator privileges, use --relay-443 for HTTPS TCP 443 relay.",
                    e
                );
                let (tx, rx) = mpsc::channel(1024);
                Ok(Self {
                    backend: GreBackend::Fallback { rx, tx },
                    local_addr,
                    remote_addr,
                    is_raw: false,
                })
            }
        }
    }

    /// Helper to force create a fallback GRE socket (useful for tests and mock environments)
    pub fn new_fallback(local_addr: Ipv4Addr, remote_addr: Ipv4Addr) -> (Self, mpsc::Sender<Vec<u8>>) {
        let (in_tx, in_rx) = mpsc::channel(1024);
        let (out_tx, _out_rx) = mpsc::channel(1024);
        let s = Self {
            backend: GreBackend::Fallback {
                rx: in_rx,
                tx: out_tx,
            },
            local_addr,
            remote_addr,
            is_raw: false,
        };
        (s, in_tx)
    }

#[cfg(windows)]
fn raw_socket_type() -> socket2::Type {
    socket2::Type::from(windows_sys::Win32::Networking::WinSock::SOCK_RAW as i32)
}

#[cfg(not(windows))]
fn raw_socket_type() -> socket2::Type {
    socket2::Type::from(3) // SOCK_RAW
}

    fn try_create_raw_socket(
        local_addr: Ipv4Addr,
        remote_addr: Ipv4Addr,
    ) -> Result<(Arc<socket2::Socket>, mpsc::Receiver<Vec<u8>>)> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            Self::raw_socket_type(),
            Some(socket2::Protocol::from(IPPROTO_GRE)),
        )?;



        // Bind to local address if specified
        if !local_addr.is_unspecified() {
            let bind_sockaddr = SocketAddr::new(IpAddr::V4(local_addr), 0);
            socket.bind(&bind_sockaddr.into())?;
        }

        let socket = Arc::new(socket);
        let (tx, rx) = mpsc::channel(2048);

        // Spawn background blocking reader for raw IP packets
        let read_sock = socket.clone();
        std::thread::Builder::new()
            .name("gre-raw-rx".to_string())
            .spawn(move || {
                let mut buf = vec![0u8; 4096];
                loop {
                    match read_sock.recv_from(unsafe {
                        &mut *(buf.as_mut_slice() as *mut [u8] as *mut [std::mem::MaybeUninit<u8>])
                    }) {
                        Ok((bytes_read, _peer)) => {
                            if bytes_read < 20 {
                                continue;
                            }

                            // IPv4 header length
                            let ihl = ((buf[0] & 0x0F) * 4) as usize;
                            if bytes_read < ihl {
                                continue;
                            }

                            let proto = buf[9];
                            if proto != (IPPROTO_GRE as u8) {
                                continue;
                            }

                            let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                            if !remote_addr.is_unspecified() && src_ip != remote_addr {
                                debug!("Ignoring GRE packet from non-peer IP: {}", src_ip);
                                continue;
                            }

                            // Slice GRE payload after IPv4 header
                            let gre_payload = buf[ihl..bytes_read].to_vec();
                            if tx.blocking_send(gre_payload).is_err() {
                                debug!("GRE RX channel receiver dropped; terminating reader thread.");
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error on raw GRE recv: {}. Ending thread.", e);
                            break;
                        }
                    }
                }
            })?;

        Ok((socket, rx))
    }

    /// Send a GRE payload (EoIP packet bytes) to the configured remote endpoint
    pub async fn send_packet(&self, payload: &[u8]) -> Result<usize> {
        match &self.backend {
            GreBackend::Raw { socket, .. } => {
                let target = SocketAddr::new(IpAddr::V4(self.remote_addr), 0);
                let socket = socket.clone();
                let data = payload.to_vec();
                let written = tokio::task::spawn_blocking(move || {
                    socket.send_to(&data, &target.into())
                })
                .await??;
                Ok(written)
            }
            GreBackend::Fallback { tx, .. } => {
                tx.send(payload.to_vec())
                    .await
                    .map_err(|e| anyhow!("Fallback GRE channel closed: {}", e))?;
                Ok(payload.len())
            }
        }
    }

    /// Receive a GRE payload from the network
    pub async fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        match &mut self.backend {
            GreBackend::Raw { rx, .. } => {
                if let Some(data) = rx.recv().await {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    Ok(len)
                } else {
                    Err(anyhow!("GRE raw socket stream closed"))
                }
            }
            GreBackend::Fallback { rx, .. } => {
                if let Some(data) = rx.recv().await {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    Ok(len)
                } else {
                    Err(anyhow!("Fallback GRE stream closed"))
                }
            }
        }
    }

    pub fn split(self) -> (GreReceiver, GreSender) {
        let remote_addr = self.remote_addr;
        match self.backend {
            GreBackend::Raw { socket, rx } => (
                GreReceiver { rx },
                GreSender {
                    backend: GreSendBackend::Raw(socket),
                    remote_addr,
                },
            ),
            GreBackend::Fallback { rx, tx } => (
                GreReceiver { rx },
                GreSender {
                    backend: GreSendBackend::Fallback(tx),
                    remote_addr,
                },
            ),
        }
    }

    pub fn is_raw(&self) -> bool {
        self.is_raw
    }

    pub fn local_addr(&self) -> Ipv4Addr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> Ipv4Addr {
        self.remote_addr
    }
}

pub enum GreSendBackend {
    Raw(Arc<socket2::Socket>),
    Fallback(mpsc::Sender<Vec<u8>>),
}

pub struct GreSender {
    backend: GreSendBackend,
    remote_addr: Ipv4Addr,
}

impl GreSender {
    pub async fn send_packet(&self, payload: &[u8]) -> Result<usize> {
        match &self.backend {
            GreSendBackend::Raw(socket) => {
                let target = SocketAddr::new(IpAddr::V4(self.remote_addr), 0);
                let socket = socket.clone();
                let data = payload.to_vec();
                let written = tokio::task::spawn_blocking(move || {
                    socket.send_to(&data, &target.into())
                })
                .await??;
                Ok(written)
            }
            GreSendBackend::Fallback(tx) => {
                tx.send(payload.to_vec())
                    .await
                    .map_err(|e| anyhow!("Fallback GRE channel closed: {}", e))?;
                Ok(payload.len())
            }
        }
    }
}

pub struct GreReceiver {
    rx: mpsc::Receiver<Vec<u8>>,
}

impl GreReceiver {
    pub async fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(data) = self.rx.recv().await {
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        } else {
            Err(anyhow!("GRE socket stream closed"))
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gre_fallback_socket_roundtrip() {
        let (mut gre, injector) = GreSocket::new_fallback(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 1),
        );

        assert!(!gre.is_raw());
        assert_eq!(gre.remote_addr(), Ipv4Addr::new(192, 168, 1, 1));

        let dummy_gre_frame = vec![0x20, 0x01, 0x64, 0x00, 0x00, 0x04, 0x64, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        injector.send(dummy_gre_frame.clone()).await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = gre.recv_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &dummy_gre_frame);
    }
}
