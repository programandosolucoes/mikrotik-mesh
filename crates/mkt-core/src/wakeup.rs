use anyhow::{anyhow, Result};
use mkt_proto::MacAddr;
use std::net::{SocketAddr, UdpSocket};
use tracing::info;

pub const PS5_WAKEUP_PORT: u16 = 9302;
pub const WOL_PORT: u16 = 9;

/// Constructs a standard Wake-on-LAN Magic Packet (6x 0xFF + 16x Target MAC = 102 bytes)
pub fn create_wol_magic_packet(target_mac: &MacAddr) -> [u8; 102] {
    let mut packet = [0u8; 102];
    packet[0..6].fill(0xFF);

    let mac_bytes = target_mac.as_bytes();
    for i in 0..16 {
        let start = 6 + (i * 6);
        packet[start..start + 6].copy_from_slice(mac_bytes);
    }

    packet
}

/// Constructs a PlayStation 5 Remote Play Wakeup UDP payload matching official Sony Remote Play / Chiaki specs
pub fn create_ps5_wakeup_payload(user_credential: Option<&str>) -> Vec<u8> {
    let cred = user_credential.unwrap_or("0").trim();
    // Official Sony PS5 Remote Play Wakeup HTTP-over-UDP structure:
    // client-type: vr / remote-play
    // auth-type: R
    // model: m
    // app-type: r
    // user-credential: <numeric or base64 PSN credential from pairing>
    // device-discovery-protocol-version: 00030010
    format!(
        "WAKEUP * HTTP/1.1\r\n\
         client-type:vr\r\n\
         auth-type:R\r\n\
         model:m\r\n\
         app-type:r\r\n\
         user-credential:{}\r\n\
         device-discovery-protocol-version:00030010\r\n\r\n",
        cred
    )
    .into_bytes()
}

/// Sends a Wake-on-LAN magic packet over UDP broadcast (ports 9 or 7)
pub fn send_wol_packet(target_mac: &MacAddr, broadcast_addr: &str) -> Result<()> {
    let packet = create_wol_magic_packet(target_mac);
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;

    let dest: SocketAddr = broadcast_addr.parse().map_err(|e| anyhow!("Invalid broadcast address: {}", e))?;
    socket.send_to(&packet, dest)?;

    info!("Wake-on-LAN magic packet sent to {} via {}", target_mac, broadcast_addr);
    Ok(())
}

/// Sends a PS5-specific Wakeup packet over UDP port 9302
pub fn send_ps5_wakeup_packet(target_ip: &str, user_credential: Option<&str>) -> Result<()> {
    let payload = create_ps5_wakeup_payload(user_credential);
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;

    let target_addr = if target_ip.contains(':') {
        target_ip.to_string()
    } else {
        format!("{}:{}", target_ip, PS5_WAKEUP_PORT)
    };

    let dest: SocketAddr = target_addr.parse().map_err(|e| anyhow!("Invalid target address: {}", e))?;
    socket.send_to(&payload, dest)?;

    info!("PlayStation 5 Wakeup packet sent to {} on port {}", dest, PS5_WAKEUP_PORT);
    Ok(())
}

/// Discovers PlayStation 5 consoles on the local network via UDP broadcast probe
pub fn discover_ps5_devices(timeout_ms: u64) -> Result<Vec<(String, String)>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms)))?;

    // Official discovery probe packet
    let probe = b"SRCH * HTTP/1.1\r\ndevice-discovery-protocol-version:00030010\r\n\r\n";
    let bcast_addr: SocketAddr = "255.255.255.255:9302".parse()?;
    socket.send_to(probe, bcast_addr)?;

    let mut found = Vec::new();
    let mut buf = [0u8; 1024];

    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(timeout_ms) {
        if let Ok((len, src)) = socket.recv_from(&mut buf) {
            let resp = String::from_utf8_lossy(&buf[..len]);
            if resp.contains("200 OK") || resp.contains("host-name") || resp.contains("device-discovery-protocol-version") {
                let host_name = resp
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("host-name:"))
                    .map(|l| l.split(':').nth(1).unwrap_or("PS5").trim().to_string())
                    .unwrap_or_else(|| "PlayStation 5".to_string());
                found.push((src.ip().to_string(), host_name));
            }
        }
    }

    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wol_magic_packet_structure() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let packet = create_wol_magic_packet(&mac);

        assert_eq!(packet.len(), 102);
        assert_eq!(&packet[0..6], &[0xFF; 6]);

        for i in 0..16 {
            let start = 6 + (i * 6);
            assert_eq!(&packet[start..start + 6], mac.as_bytes());
        }
    }

    #[test]
    fn test_ps5_wakeup_payload() {
        let payload = create_ps5_wakeup_payload(Some("-123456789"));
        let text = String::from_utf8(payload).unwrap();

        assert!(text.contains("WAKEUP * HTTP/1.1"));
        assert!(text.contains("device-discovery-protocol-version:0003001"));
        assert!(text.contains("user-credential:-123456789"));
    }
}
