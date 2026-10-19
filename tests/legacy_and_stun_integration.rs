use anyhow::Result;
use mkt_crypto::{compute_legacy_md5_response, verify_legacy_response};
use mkt_net::StunMessage;
use mkt_proto::{MacAddr, MacTelnetHeader, MacTelnetPacket, PacketType};

#[tokio::test]
async fn test_stun_two_nodes_peer_exchange() -> Result<()> {
    // Simulates two Linux containers / nodes exchanging candidates through the STUN Gateway protocol
    let tunnel_id = 500u16;

    // Node 1 announces its local endpoint
    let node1_msg = StunMessage::RegisterPeer {
        tunnel_id,
        peer_name: "mkt-linux-node1".to_string(),
        auth_token: "mkt_secure_token_2026".to_string(),
        listening_port: Some(4701),
    };
    let json_node1 = node1_msg.to_json()?;
    assert!(json_node1.contains("mkt-linux-node1"));

    // Hub responds with RegistrationAck and observed IP
    let hub_ack = StunMessage::RegistrationAck {
        tunnel_id,
        observed_public_addr: "189.98.161.197:4701".parse()?,
        hub_status: "online".to_string(),
    };
    let json_ack = hub_ack.to_json()?;
    assert!(json_ack.contains("189.98.161.197:4701"));

    // Node 2 queries peer info for tunnel 500
    let query = StunMessage::QueryPeer { tunnel_id };
    assert_eq!(query, StunMessage::from_json(&query.to_json()?)?);

    // Hub returns PeerInfo with Node 1's observed endpoint
    let peer_info = StunMessage::PeerInfo {
        tunnel_id,
        remote_observed_addr: Some("189.98.161.197:4701".parse()?),
        requires_relay: false,
    };
    let parsed_info = StunMessage::from_json(&peer_info.to_json()?)?;
    assert_eq!(peer_info, parsed_info);

    println!("STUN message coordination between 2 nodes verified successfully.");
    Ok(())
}

#[tokio::test]
async fn test_legacy_mikrotik_v4_v5_md5_authentication() -> Result<()> {
    // RouterOS < v6.43 (v4, v5, early v6) uses standard MD5 challenge-response
    let challenge: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];
    let password = "admin_legacy_pass";

    // 1. Client computes response: MD5(0x00 + password + challenge)
    let client_response = compute_legacy_md5_response(password, &challenge);
    assert_ne!(client_response, [0u8; 16]);

    // 2. Server verifies response matches expected
    let expected = compute_legacy_md5_response(password, &challenge);
    assert!(verify_legacy_response(&expected, &client_response));

    // 3. Wrong password must fail
    let wrong_response = compute_legacy_md5_response("wrong_pass", &challenge);
    assert!(!verify_legacy_response(&expected, &wrong_response));

    println!("Legacy MikroTik v4/v5 MD5 challenge-response verified successfully.");
    Ok(())
}

#[tokio::test]
async fn test_mactelnet_v4_v5_raw_plaintext_session() -> Result<()> {
    // RouterOS v4/v5 plaintext session interaction without EC-SRP5
    let client_mac = MacAddr([0x00, 0x0C, 0x42, 0x11, 0x22, 0x33]);
    let router_mac = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    let session_id = 3001u16;

    // StartSession packet
    let syn = MacTelnetHeader::new(PacketType::StartSession, client_mac, router_mac, session_id, 1);
    let syn_pkt = MacTelnetPacket::new(syn, Vec::new());
    let mut buf = vec![0u8; 256];
    let len = syn_pkt.serialize(&mut buf)?;
    let parsed = MacTelnetPacket::parse(&buf[..len])?;
    assert_eq!(parsed.header.packet_type, PacketType::StartSession);
    assert_eq!(parsed.header.session_id, session_id);

    // Legacy Data packet (Terminal command: /interface print)
    let cmd = b"/interface print\r\n";
    let data_hdr = MacTelnetHeader::new(PacketType::Data, client_mac, router_mac, session_id, 2);
    let data_pkt = MacTelnetPacket::new(data_hdr, cmd.to_vec());
    let len2 = data_pkt.serialize(&mut buf)?;
    let parsed_data = MacTelnetPacket::parse(&buf[..len2])?;
    assert_eq!(parsed_data.payload, cmd);

    // Server Ack packet
    let ack = MacTelnetPacket::ack(router_mac, client_mac, session_id, 2);
    let len3 = ack.serialize(&mut buf)?;
    let parsed_ack = MacTelnetPacket::parse(&buf[..len3])?;
    assert_eq!(parsed_ack.header.packet_type, PacketType::Ack);

    println!("Legacy MikroTik v4/v5 MAC-Telnet packet exchange verified.");
    Ok(())
}
