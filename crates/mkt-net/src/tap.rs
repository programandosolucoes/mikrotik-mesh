use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub trait TapReader: Send + Sync {
    fn read_frame<'a>(&'a mut self, buf: &'a mut [u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>>;
}

pub trait TapWriter: Send + Sync {
    fn write_frame<'a>(&'a mut self, frame: &'a [u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}

pub trait TapDevice: TapReader + TapWriter + Send + Sync {
    fn name(&self) -> &str;
    fn clone_writer(&self) -> Result<Box<dyn TapWriter>>;
}

/// Simulated in-memory TAP device (works across Windows, macOS, and Linux without drivers)
pub struct MockTapDevice {
    name: String,
    rx_queue: Arc<Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    tx_sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    outbound_sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    outbound_rx: Arc<Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
}

/// Host-side handle for injecting and receiving frames to/from a MockTapDevice (simulating OS/user traffic)
#[derive(Clone)]
pub struct MockTapHostHandle {
    name: String,
    to_tunnel_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    from_tunnel_rx: Arc<Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
}

impl MockTapHostHandle {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Injects an Ethernet frame into the TAP device (as if sent by the local OS network stack)
    pub async fn inject_frame(&self, frame: &[u8]) -> Result<()> {
        self.to_tunnel_tx
            .send(frame.to_vec())
            .await
            .map_err(|e| anyhow!("Failed to inject frame into TAP: {}", e))
    }

    /// Receives an Ethernet frame that the tunnel delivered to the TAP interface (as if arriving at the local OS)
    pub async fn recv_frame(&self) -> Option<Vec<u8>> {
        let mut rx = self.from_tunnel_rx.lock().await;
        rx.recv().await
    }

    /// Receives an Ethernet frame with an explicit timeout
    pub async fn recv_frame_timeout(&self, timeout: std::time::Duration) -> Result<Vec<u8>> {
        tokio::time::timeout(timeout, async {
            let mut rx = self.from_tunnel_rx.lock().await;
            rx.recv().await.ok_or_else(|| anyhow!("TAP channel closed"))
        })
        .await
        .map_err(|_| anyhow!("Timeout waiting for frame on TAP interface"))?
    }
}

pub struct MockTapWriter {
    outbound_sender: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl TapWriter for MockTapWriter {
    fn write_frame<'a>(&'a mut self, frame: &'a [u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        let sender = self.outbound_sender.clone();
        let data = frame.to_vec();
        Box::pin(async move {
            let _ = sender.send(data).await;
            Ok(())
        })
    }
}

impl MockTapDevice {
    /// Creates a pair of (MockTapDevice, MockTapHostHandle) for testing bidirectional data plane
    pub fn create_pair(name: &str) -> (Self, MockTapHostHandle) {
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(1024);
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(1024);

        let device = Self {
            name: name.to_string(),
            rx_queue: Arc::new(Mutex::new(in_rx)),
            tx_sender: in_tx.clone(),
            outbound_sender: out_tx,
            outbound_rx: Arc::new(Mutex::new(tokio::sync::mpsc::channel(1).1)),
        };

        let host = MockTapHostHandle {
            name: name.to_string(),
            to_tunnel_tx: in_tx,
            from_tunnel_rx: Arc::new(Mutex::new(out_rx)),
        };

        (device, host)
    }

    pub fn new(name: &str) -> (Self, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(1024);
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(1024);
        let (_dummy_tx, dummy_rx) = tokio::sync::mpsc::channel(1);

        (
            Self {
                name: name.to_string(),
                rx_queue: Arc::new(Mutex::new(in_rx)),
                tx_sender: in_tx,
                outbound_sender: out_tx,
                outbound_rx: Arc::new(Mutex::new(out_rx)),
            },
            dummy_rx,
        )
    }

    pub fn sender(&self) -> tokio::sync::mpsc::Sender<Vec<u8>> {
        self.tx_sender.clone()
    }

    pub async fn recv_outbound(&self) -> Option<Vec<u8>> {
        let mut rx = self.outbound_rx.lock().await;
        rx.recv().await
    }
}


impl TapReader for MockTapDevice {
    fn read_frame<'a>(&'a mut self, buf: &'a mut [u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut rx = self.rx_queue.lock().await;
            if let Some(frame) = rx.recv().await {
                let len = frame.len().min(buf.len());
                buf[..len].copy_from_slice(&frame[..len]);
                Ok(len)
            } else {
                Err(anyhow!("TAP channel closed"))
            }
        })
    }
}

impl TapWriter for MockTapDevice {
    fn write_frame<'a>(&'a mut self, frame: &'a [u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        let sender = self.outbound_sender.clone();
        let data = frame.to_vec();
        Box::pin(async move {
            sender
                .send(data)
                .await
                .map_err(|e| anyhow!("Failed to send frame to outbound queue: {}", e))?;
            Ok(())
        })
    }
}

impl TapDevice for MockTapDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn clone_writer(&self) -> Result<Box<dyn TapWriter>> {
        Ok(Box::new(MockTapWriter {
            outbound_sender: self.outbound_sender.clone(),
        }))
    }
}

#[cfg(target_os = "linux")]
pub struct LinuxTapWriter {
    fd: std::fs::File,
}

#[cfg(target_os = "linux")]
impl TapWriter for LinuxTapWriter {
    fn write_frame<'a>(&'a mut self, frame: &'a [u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        use std::io::Write;
        let mut fd = match self.fd.try_clone() {
            Ok(f) => f,
            Err(e) => return Box::pin(async move { Err(anyhow!("Failed to clone TAP fd: {}", e)) }),
        };
        let data = frame.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                fd.write_all(&data).map_err(|e| anyhow!("TAP write error: {}", e))
            })
            .await?
        })
    }
}

#[cfg(target_os = "linux")]
pub struct LinuxNativeTap {
    name: String,
    fd: std::fs::File,
}

#[cfg(target_os = "linux")]
impl LinuxNativeTap {
    pub fn create(dev_name: &str) -> Result<Self> {
        use std::os::unix::io::FromRawFd;

        info!("Creating native Linux TAP device: {}", dev_name);
        let fd = unsafe {
            let raw_fd = libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR,
            );
            if raw_fd < 0 {
                return Err(anyhow!("Failed to open /dev/net/tun. Check CAP_NET_ADMIN permissions."));
            }

            let mut ifr: libc::ifreq = std::mem::zeroed();
            ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;

            let bytes = dev_name.as_bytes();
            let len = bytes.len().min(libc::IFNAMSIZ - 1);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ifr.ifr_name.as_mut_ptr() as *mut u8, len);

            const TUNSETIFF: libc::c_ulong = 0x400454ca;
            if libc::ioctl(raw_fd, TUNSETIFF, &mut ifr) < 0 {
                libc::close(raw_fd);
                return Err(anyhow!("ioctl(TUNSETIFF) failed for {}", dev_name));
            }

            raw_fd
        };

        Ok(Self {
            name: dev_name.to_string(),
            fd: unsafe { std::fs::File::from_raw_fd(fd) },
        })
    }
}

#[cfg(target_os = "linux")]
impl TapReader for LinuxNativeTap {
    fn read_frame<'a>(&'a mut self, buf: &'a mut [u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>> {
        use std::io::Read;
        let mut fd = match self.fd.try_clone() {
            Ok(f) => f,
            Err(e) => return Box::pin(async move { Err(anyhow!("Failed to clone TAP fd: {}", e)) }),
        };
        let buf_len = buf.len();
        Box::pin(async move {
            let (res, read_buf) = tokio::task::spawn_blocking(move || {
                let mut temp_buf = vec![0u8; buf_len];
                let n = fd.read(&mut temp_buf).map_err(|e| anyhow!("TAP read error: {}", e))?;
                temp_buf.truncate(n);
                Ok::<_, anyhow::Error>((n, temp_buf))
            })
            .await??;

            buf[..res].copy_from_slice(&read_buf);
            Ok(res)
        })
    }
}

#[cfg(target_os = "linux")]
impl TapWriter for LinuxNativeTap {
    fn write_frame<'a>(&'a mut self, frame: &'a [u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        use std::io::Write;
        let mut fd = match self.fd.try_clone() {
            Ok(f) => f,
            Err(e) => return Box::pin(async move { Err(anyhow!("Failed to clone TAP fd: {}", e)) }),
        };
        let data = frame.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                fd.write_all(&data).map_err(|e| anyhow!("TAP write error: {}", e))
            })
            .await?
        })
    }
}

#[cfg(target_os = "linux")]
impl TapDevice for LinuxNativeTap {
    fn name(&self) -> &str {
        &self.name
    }

    fn clone_writer(&self) -> Result<Box<dyn TapWriter>> {
        Ok(Box::new(LinuxTapWriter {
            fd: self.fd.try_clone()?,
        }))
    }
}

pub fn create_tap_device(name: &str) -> Result<Box<dyn TapDevice>> {
    #[cfg(target_os = "linux")]
    {
        match LinuxNativeTap::create(name) {
            Ok(tap) => return Ok(Box::new(tap)),
            Err(e) => {
                info!("Could not initialize native Linux TAP ({}), falling back to portable mock TAP.", e);
            }
        }
    }

    info!("Initializing portable userspace TAP interface: {}", name);
    let (mock, _rx) = MockTapDevice::new(name);
    Ok(Box::new(mock))
}
