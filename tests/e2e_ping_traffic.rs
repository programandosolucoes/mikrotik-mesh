use anyhow::{anyhow, Result};
use mkt_core::{EoipTunnel, EoipTunnelConfig};
use mkt_net::{HttpsRelayServer, MockTapDevice, RelayHub};
use mkt_proto::MacAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Computes standard RFC 1071 Internet Checksum
fn compute_internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum = sum.wrapping_add(word as u32);
        i += 2;
    }
    if i < data.len() {
        let word = u16::from_be_bytes([data[i], 0]);
        sum = sum.wrapping_add(word as u32);
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Constructs a valid Ethernet II + IPv4 + ICMP Echo Request / Reply frame
fn build_icmp_echo_frame(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    icmp_type: u8, // 8 = Echo Request, 0 = Echo Reply
    ident: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    // 1. ICMP Section (8 bytes header + payload)
    let icmp_len = 8 + payload.len();
    let mut icmp = vec![0u8; icmp_len];
    icmp[0] = icmp_type;
    icmp[1] = 0; // code
    icmp[2..4].copy_from_slice(&[0, 0]); // csum placeholder
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let icmp_csum = compute_internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

    // 2. IPv4 Section (20 bytes header)
    let ip_len = 20 + icmp_len;
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45; // IPv4, Header Length 20 bytes
    ip[1] = 0x00; // DSCP/ECN
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&ident.to_be_bytes()); // IP identification
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag
    ip[8] = 64;   // TTL
    ip[9] = 1;    // Protocol: ICMP (1)
    ip[10..12].copy_from_slice(&[0, 0]); // csum placeholder
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);
    let ip_csum = compute_internet_checksum(&ip);
    ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // 3. Ethernet II Section (14 bytes)
    let mut frame = Vec::with_capacity(14 + ip.len() + icmp.len());
    frame.extend_from_slice(dst_mac.as_bytes());
    frame.extend_from_slice(src_mac.as_bytes());
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&icmp);
    frame
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedIcmpFrame {
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    icmp_type: u8,
    icmp_code: u8,
    ident: u16,
    seq: u16,
    payload: Vec<u8>,
}

fn parse_icmp_frame(raw: &[u8]) -> Option<ParsedIcmpFrame> {
    if raw.len() < 14 + 20 + 8 {
        return None;
    }
    let dst_mac = MacAddr(raw[0..6].try_into().ok()?);
    let src_mac = MacAddr(raw[6..12].try_into().ok()?);
    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    if ethertype != 0x0800 {
        return None;
    }

    let ip_header = &raw[14..34];
    if (ip_header[0] >> 4) != 4 || ip_header[9] != 1 {
        return None;
    }
    let src_ip: [u8; 4] = ip_header[12..16].try_into().ok()?;
    let dst_ip: [u8; 4] = ip_header[16..20].try_into().ok()?;

    let icmp_data = &raw[34..];
    let icmp_type = icmp_data[0];
    let icmp_code = icmp_data[1];
    let ident = u16::from_be_bytes([icmp_data[4], icmp_data[5]]);
    let seq = u16::from_be_bytes([icmp_data[6], icmp_data[7]]);
    let payload = icmp_data[8..].to_vec();

    Some(ParsedIcmpFrame {
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        icmp_type,
        icmp_code,
        ident,
        seq,
        payload,
    })
}

/// Helper that spawns a local HTTPS TCP 443 RelayHub multiplexer on an ephemeral port
async fn spawn_test_relay_server() -> Result<(String, Arc<RelayHub>)> {
    let server = Arc::new(HttpsRelayServer::bind("127.0.0.1:0").await?);
    let addr = server.listener.local_addr()?.to_string();
    let hub = Arc::new(RelayHub::new());
    let hub_clone = hub.clone();

    tokio::spawn(async move {
        let _ = server.run_hub(hub_clone).await;
    });

    Ok((addr, hub))
}

#[tokio::test]
async fn test_e2e_relay_plaintext_bidirectional_ping() -> Result<()> {
    println!("=== TEST: E2E Plaintext Bidirectional Ping over Relay Server ===");
    let (relay_addr, _hub) = spawn_test_relay_server().await?;

    let mac_host_a = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let mac_host_b = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let ip_a = [10, 200, 1, 1];
    let ip_b = [10, 200, 1, 2];
    let tunnel_id = 101;

    // 1. Create Endpoint A
    let (tap_a, host_a) = MockTapDevice::create_pair("tap-side-a");
    let config_a = EoipTunnelConfig {
        tunnel_id,
        local_addr: "0.0.0.0".to_string(),
        remote_addr: relay_addr.clone(),
        tap_name: "tap-side-a".to_string(),
        use_https_relay: true,
        ipsec_secret: None,
        allowed_macs: Vec::new(),
    };
    let tunnel_a = Arc::new(EoipTunnel::with_tap(config_a, Box::new(tap_a))?);
    tunnel_a.clone().start_https_relay_loop().await?;

    // 2. Create Endpoint B
    let (tap_b, host_b) = MockTapDevice::create_pair("tap-side-b");
    let config_b = EoipTunnelConfig {
        tunnel_id,
        local_addr: "0.0.0.0".to_string(),
        remote_addr: relay_addr.clone(),
        tap_name: "tap-side-b".to_string(),
        use_https_relay: true,
        ipsec_secret: None,
        allowed_macs: Vec::new(),
    };
    let tunnel_b = Arc::new(EoipTunnel::with_tap(config_b, Box::new(tap_b))?);
    tunnel_b.clone().start_https_relay_loop().await?;

    // Allow connection and keepalive registration in hub
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 3. Host A injects ICMP Echo Request into TAP A
    let ping_payload = b"MIKROTIK_MESH_E2E_PING_REQUEST_1";
    let ping_req = build_icmp_echo_frame(
        mac_host_a,
        mac_host_b,
        ip_a,
        ip_b,
        8, // Echo Request
        0x1001,
        1,
        ping_payload,
    );

    let start_time = Instant::now();
    host_a.inject_frame(&ping_req).await?;

    // 4. Host B receives frame from TAP B
    let received_b = host_b
        .recv_frame_timeout(Duration::from_secs(2))
        .await
        .map_err(|e| anyhow!("Host B did not receive ICMP Echo Request: {}", e))?;

    let parsed_req = parse_icmp_frame(&received_b).expect("Host B received invalid ICMP frame");
    assert_eq!(parsed_req.src_mac, mac_host_a);
    assert_eq!(parsed_req.dst_mac, mac_host_b);
    assert_eq!(parsed_req.src_ip, ip_a);
    assert_eq!(parsed_req.dst_ip, ip_b);
    assert_eq!(parsed_req.icmp_type, 8); // Echo Request
    assert_eq!(parsed_req.ident, 0x1001);
    assert_eq!(parsed_req.seq, 1);
    assert_eq!(parsed_req.payload, ping_payload);

    // 5. Host B responds with ICMP Echo Reply (swapping MACs and IPs)
    let ping_reply = build_icmp_echo_frame(
        mac_host_b,
        mac_host_a,
        ip_b,
        ip_a,
        0, // Echo Reply
        0x1001,
        1,
        ping_payload,
    );
    host_b.inject_frame(&ping_reply).await?;

    // 6. Host A receives ICMP Echo Reply from TAP A
    let received_a = host_a
        .recv_frame_timeout(Duration::from_secs(2))
        .await
        .map_err(|e| anyhow!("Host A did not receive ICMP Echo Reply: {}", e))?;

    let rtt = start_time.elapsed();
    let parsed_reply = parse_icmp_frame(&received_a).expect("Host A received invalid ICMP frame");
    assert_eq!(parsed_reply.src_mac, mac_host_b);
    assert_eq!(parsed_reply.dst_mac, mac_host_a);
    assert_eq!(parsed_reply.src_ip, ip_b);
    assert_eq!(parsed_reply.dst_ip, ip_a);
    assert_eq!(parsed_reply.icmp_type, 0); // Echo Reply
    assert_eq!(parsed_reply.ident, 0x1001);
    assert_eq!(parsed_reply.seq, 1);
    assert_eq!(parsed_reply.payload, ping_payload);

    println!(
        "E2E Plaintext Ping Roundtrip SUCCESS! RTT: {:.3}ms",
        rtt.as_secs_f64() * 1000.0
    );

    // 7. Verify Metrics
    let stats_a = tunnel_a.get_stats();
    let stats_b = tunnel_b.get_stats();
    println!("Endpoint A Stats: {:?}", stats_a);
    println!("Endpoint B Stats: {:?}", stats_b);

    assert!(stats_a.tx_packets >= 1, "Endpoint A must have tx_packets >= 1");
    assert!(stats_a.rx_packets >= 1, "Endpoint A must have rx_packets >= 1");
    assert_eq!(stats_a.dropped_packets, 0, "Endpoint A dropped packets must be 0");

    assert!(stats_b.tx_packets >= 1, "Endpoint B must have tx_packets >= 1");
    assert!(stats_b.rx_packets >= 1, "Endpoint B must have rx_packets >= 1");
    assert_eq!(stats_b.dropped_packets, 0, "Endpoint B dropped packets must be 0");

    Ok(())
}

#[tokio::test]
async fn test_e2e_relay_encrypted_chacha20_bidirectional_ping() -> Result<()> {
    println!("=== TEST: E2E ChaCha20-Poly1305 AEAD Encrypted Bidirectional Ping ===");
    let (relay_addr, _hub) = spawn_test_relay_server().await?;

    let mac_host_a = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let mac_host_b = MacAddr([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    let ip_a = [192, 168, 88, 10];
    let ip_b = [192, 168, 88, 20];
    let tunnel_id = 777;
    let shared_passphrase = "MikroTikMeshUltraSecureSecret2026!#$";

    // 1. Create Endpoint A with Encryption
    let (tap_a, host_a) = MockTapDevice::create_pair("tap-enc-a");
    let config_a = EoipTunnelConfig {
        tunnel_id,
        local_addr: "0.0.0.0".to_string(),
        remote_addr: relay_addr.clone(),
        tap_name: "tap-enc-a".to_string(),
        use_https_relay: true,
        ipsec_secret: Some(shared_passphrase.to_string()),
        allowed_macs: Vec::new(),
    };
    let tunnel_a = Arc::new(EoipTunnel::with_tap(config_a, Box::new(tap_a))?);
    tunnel_a.clone().start_https_relay_loop().await?;

    // 2. Create Endpoint B with identical Encryption Key
    let (tap_b, host_b) = MockTapDevice::create_pair("tap-enc-b");
    let config_b = EoipTunnelConfig {
        tunnel_id,
        local_addr: "0.0.0.0".to_string(),
        remote_addr: relay_addr.clone(),
        tap_name: "tap-enc-b".to_string(),
        use_https_relay: true,
        ipsec_secret: Some(shared_passphrase.to_string()),
        allowed_macs: Vec::new(),
    };
    let tunnel_b = Arc::new(EoipTunnel::with_tap(config_b, Box::new(tap_b))?);
    tunnel_b.clone().start_https_relay_loop().await?;

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 3. Inject Ping Request from Host A
    let ping_payload = b"ENCRYPTED_CHACHA20_AUTHENTICATED_PING";
    let ping_req = build_icmp_echo_frame(
        mac_host_a,
        mac_host_b,
        ip_a,
        ip_b,
        8,
        0x55AA,
        42,
        ping_payload,
    );

    let start_time = Instant::now();
    host_a.inject_frame(&ping_req).await?;

    // 4. Host B receives decrypted and authenticated frame
    let received_b = host_b
        .recv_frame_timeout(Duration::from_secs(2))
        .await
        .map_err(|e| anyhow!("Host B did not receive encrypted ICMP Echo Request: {}", e))?;

    let parsed_req = parse_icmp_frame(&received_b).expect("Host B received invalid ICMP frame");
    assert_eq!(parsed_req.src_mac, mac_host_a);
    assert_eq!(parsed_req.dst_mac, mac_host_b);
    assert_eq!(parsed_req.ident, 0x55AA);
    assert_eq!(parsed_req.seq, 42);
    assert_eq!(parsed_req.payload, ping_payload);

    // 5. Host B sends Echo Reply back
    let ping_reply = build_icmp_echo_frame(
        mac_host_b,
        mac_host_a,
        ip_b,
        ip_a,
        0,
        0x55AA,
        42,
        ping_payload,
    );
    host_b.inject_frame(&ping_reply).await?;

    // 6. Host A receives decrypted Echo Reply
    let received_a = host_a
        .recv_frame_timeout(Duration::from_secs(2))
        .await
        .map_err(|e| anyhow!("Host A did not receive encrypted ICMP Echo Reply: {}", e))?;

    let rtt = start_time.elapsed();
    let parsed_reply = parse_icmp_frame(&received_a).expect("Host A received invalid ICMP frame");
    assert_eq!(parsed_reply.src_mac, mac_host_b);
    assert_eq!(parsed_reply.dst_mac, mac_host_a);
    assert_eq!(parsed_reply.icmp_type, 0);
    assert_eq!(parsed_reply.ident, 0x55AA);
    assert_eq!(parsed_reply.seq, 42);
    assert_eq!(parsed_reply.payload, ping_payload);

    println!(
        "E2E Encrypted Ping Roundtrip SUCCESS! RTT: {:.3}ms",
        rtt.as_secs_f64() * 1000.0
    );

    let stats_a = tunnel_a.get_stats();
    let stats_b = tunnel_b.get_stats();
    println!("Endpoint A Stats: {:?}", stats_a);
    println!("Endpoint B Stats: {:?}", stats_b);
    assert!(stats_a.tx_packets >= 1);
    assert!(stats_a.rx_packets >= 1);
    assert_eq!(stats_a.dropped_packets, 0);
    assert_eq!(stats_b.dropped_packets, 0);

    Ok(())
}

#[tokio::test]
async fn test_e2e_mac_allowlist_filtering() -> Result<()> {
    println!("=== TEST: E2E MAC Allowlist Filtering Enforcement ===");
    let (relay_addr, _hub) = spawn_test_relay_server().await?;

    let allowed_ps5_mac = MacAddr([0x00, 0xD9, 0xD1, 0x11, 0x22, 0x33]);
    let allowed_pc_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let rogue_mac = MacAddr([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x99]);

    let ip_a = [192, 168, 1, 10];
    let ip_b = [192, 168, 1, 50];
    let tunnel_id = 888;

    // Endpoint A: Allowlist only contains PS5 and PC MACs
    let (tap_a, host_a) = MockTapDevice::create_pair("tap-filter-a");
    let config_a = EoipTunnelConfig {
        tunnel_id,
        local_addr: "0.0.0.0".to_string(),
        remote_addr: relay_addr.clone(),
        tap_name: "tap-filter-a".to_string(),
        use_https_relay: true,
        ipsec_secret: None,
        allowed_macs: vec![allowed_ps5_mac, allowed_pc_mac],
    };
    let tunnel_a = Arc::new(EoipTunnel::with_tap(config_a, Box::new(tap_a))?);
    tunnel_a.clone().start_https_relay_loop().await?;

    // Endpoint B
    let (tap_b, host_b) = MockTapDevice::create_pair("tap-filter-b");
    let config_b = EoipTunnelConfig {
        tunnel_id,
        local_addr: "0.0.0.0".to_string(),
        remote_addr: relay_addr.clone(),
        tap_name: "tap-filter-b".to_string(),
        use_https_relay: true,
        ipsec_secret: None,
        allowed_macs: vec![allowed_ps5_mac, allowed_pc_mac],
    };
    let tunnel_b = Arc::new(EoipTunnel::with_tap(config_b, Box::new(tap_b))?);
    tunnel_b.clone().start_https_relay_loop().await?;

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 1. Inject Unauthorized Frame from Rogue MAC -> Must be blocked!
    let rogue_frame = build_icmp_echo_frame(
        rogue_mac,
        MacAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        [192, 168, 1, 99],
        [192, 168, 1, 255],
        8,
        0x9999,
        1,
        b"ROGUE_ATTACK_PACKET",
    );
    host_a.inject_frame(&rogue_frame).await?;

    // Verify Host B does NOT receive the rogue frame
    let rogue_received = host_b.recv_frame_timeout(Duration::from_millis(300)).await;
    assert!(rogue_received.is_err(), "Rogue frame MUST be dropped and never reach Host B");

    let stats_a = tunnel_a.get_stats();
    assert_eq!(stats_a.filtered_mac_packets, 1, "Endpoint A filtered_mac_packets must increment");

    // 2. Inject Authorized Frame from PC to PS5 -> Must pass!
    let authorized_frame = build_icmp_echo_frame(
        allowed_pc_mac,
        allowed_ps5_mac,
        ip_a,
        ip_b,
        8,
        0x1234,
        2,
        b"AUTHORIZED_PS5_TRAFFIC",
    );
    host_a.inject_frame(&authorized_frame).await?;

    let auth_received = host_b
        .recv_frame_timeout(Duration::from_secs(2))
        .await
        .expect("Authorized frame MUST reach Host B");

    let parsed = parse_icmp_frame(&auth_received).unwrap();
    assert_eq!(parsed.src_mac, allowed_pc_mac);
    assert_eq!(parsed.dst_mac, allowed_ps5_mac);
    assert_eq!(parsed.payload, b"AUTHORIZED_PS5_TRAFFIC");

    println!("MAC Filtering Test Passed: Rogue frame blocked, authorized frame delivered successfully.");
    Ok(())
}

#[tokio::test]
async fn test_e2e_burst_traffic_and_latency_metrics() -> Result<()> {
    println!("=== TEST: E2E Burst Traffic (10 Sequential Pings) & Latency Stats ===");
    let (relay_addr, _hub) = spawn_test_relay_server().await?;

    let mac_a = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
    let mac_b = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x02]);
    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let tunnel_id = 999;

    let (tap_a, host_a) = MockTapDevice::create_pair("tap-burst-a");
    let (tap_b, host_b) = MockTapDevice::create_pair("tap-burst-b");

    let config_a = EoipTunnelConfig {
        tunnel_id,
        local_addr: "0.0.0.0".to_string(),
        remote_addr: relay_addr.clone(),
        tap_name: "tap-burst-a".to_string(),
        use_https_relay: true,
        ipsec_secret: Some("BurstKey2026".to_string()),
        allowed_macs: Vec::new(),
    };
    let config_b = EoipTunnelConfig {
        tunnel_id,
        local_addr: "0.0.0.0".to_string(),
        remote_addr: relay_addr.clone(),
        tap_name: "tap-burst-b".to_string(),
        use_https_relay: true,
        ipsec_secret: Some("BurstKey2026".to_string()),
        allowed_macs: Vec::new(),
    };

    let tunnel_a = Arc::new(EoipTunnel::with_tap(config_a, Box::new(tap_a))?);
    let tunnel_b = Arc::new(EoipTunnel::with_tap(config_b, Box::new(tap_b))?);

    tunnel_a.clone().start_https_relay_loop().await?;
    tunnel_b.clone().start_https_relay_loop().await?;

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Spawn Host B responder task
    let host_b_responder = host_b.clone();
    let responder_task = tokio::spawn(async move {
        for _ in 0..10 {
            if let Ok(frame) = host_b_responder.recv_frame_timeout(Duration::from_secs(3)).await {
                if let Some(req) = parse_icmp_frame(&frame) {
                    if req.icmp_type == 8 {
                        // Generate Echo Reply
                        let reply = build_icmp_echo_frame(
                            req.dst_mac,
                            req.src_mac,
                            req.dst_ip,
                            req.src_ip,
                            0, // Reply
                            req.ident,
                            req.seq,
                            &req.payload,
                        );
                        let _ = host_b_responder.inject_frame(&reply).await;
                    }
                }
            }
        }
    });

    let mut rtt_measurements = Vec::new();
    let count = 10;

    for seq in 1..=count {
        let payload = format!("BURST_PING_SEQ_{}", seq).into_bytes();
        let ping_req = build_icmp_echo_frame(
            mac_a,
            mac_b,
            ip_a,
            ip_b,
            8,
            0x4000,
            seq as u16,
            &payload,
        );

        let t0 = Instant::now();
        host_a.inject_frame(&ping_req).await?;

        let reply = host_a
            .recv_frame_timeout(Duration::from_secs(2))
            .await
            .unwrap_or_else(|_| panic!("Failed to receive reply for seq {}", seq));

        let elapsed = t0.elapsed();
        rtt_measurements.push(elapsed);

        let parsed = parse_icmp_frame(&reply).expect("Valid reply frame");
        assert_eq!(parsed.seq, seq as u16);
        assert_eq!(parsed.icmp_type, 0);
        assert_eq!(parsed.payload, payload);
    }

    responder_task.await?;

    let total_rtt: Duration = rtt_measurements.iter().sum();
    let avg_rtt = total_rtt / count as u32;
    let min_rtt = rtt_measurements.iter().min().unwrap();
    let max_rtt = rtt_measurements.iter().max().unwrap();

    println!("------------------------------------------------------------");
    println!("  E2E PING TRAFFIC BURST METRICS REPORT                     ");
    println!("------------------------------------------------------------");
    println!("  Pings Transmitted:       {}", count);
    println!("  Pings Received:          {}", count);
    println!("  Packet Loss:             0.0%");
    println!("  Min Latency (RTT):       {:.3} ms", min_rtt.as_secs_f64() * 1000.0);
    println!("  Avg Latency (RTT):       {:.3} ms", avg_rtt.as_secs_f64() * 1000.0);
    println!("  Max Latency (RTT):       {:.3} ms", max_rtt.as_secs_f64() * 1000.0);
    let stats_a = tunnel_a.get_stats();
    let stats_b = tunnel_b.get_stats();
    println!("  Tunnel A Tx / Rx / Drop: {} / {} / {}", stats_a.tx_packets, stats_a.rx_packets, stats_a.dropped_packets);
    println!("  Tunnel B Tx / Rx / Drop: {} / {} / {}", stats_b.tx_packets, stats_b.rx_packets, stats_b.dropped_packets);
    println!("------------------------------------------------------------");

    assert_eq!(stats_a.dropped_packets, 0);
    assert_eq!(stats_b.dropped_packets, 0);
    assert!(stats_a.tx_packets >= 10);
    assert!(stats_a.rx_packets >= 10);

    Ok(())
}
