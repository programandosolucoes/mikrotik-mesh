use anyhow::{anyhow, Result};
use mkt_crypto::{SrpClientSession, SrpServerSession};
use mkt_proto::{MacAddr, MacTelnetHeader, MacTelnetPacket, PacketType};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tracing::info;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SessionState {
    Disconnected,
    Connecting,
    AuthenticatingSrp,
    Connected,
    Terminating,
}

pub struct MacTelnetClientEngine {
    pub state: SessionState,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub session_id: u16,
    pub username: String,
    password: String,
    sequence: Arc<AtomicU32>,
    srp_session: Option<SrpClientSession>,
    derived_session_key: Option<[u8; 32]>,
}

impl MacTelnetClientEngine {
    pub fn new(src_mac: MacAddr, dst_mac: MacAddr, session_id: u16, username: &str, password: &str) -> Self {
        Self {
            state: SessionState::Disconnected,
            src_mac,
            dst_mac,
            session_id,
            username: username.to_string(),
            password: password.to_string(),
            sequence: Arc::new(AtomicU32::new(1)),
            srp_session: None,
            derived_session_key: None,
        }
    }

    /// Step 1: Create SYN / StartSession packet
    pub fn create_start_session_packet(&mut self) -> MacTelnetPacket {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let header = MacTelnetHeader::new(PacketType::StartSession, self.src_mac, self.dst_mac, self.session_id, seq);
        self.state = SessionState::Connecting;
        MacTelnetPacket::new(header, Vec::new())
    }

    /// Step 2: Handle incoming Challenge from Server (or RouterOS) and respond with EC-SRP public key & proof
    pub fn handle_challenge_and_generate_proof(
        &mut self,
        salt: &[u8],
        server_pub_b: &[u8; 32],
    ) -> Result<(MacTelnetPacket, [u8; 32])> {
        let mut srp = SrpClientSession::new(&self.username, &self.password);
        let (session_key, client_m1) = srp.process_challenge(salt, server_pub_b)?;

        // Payload encodes: [CLIENT_PUB_A: 32 bytes | CLIENT_M1: 32 bytes]
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&srp.client_public_a);
        payload.extend_from_slice(&client_m1);

        self.srp_session = Some(srp);
        self.derived_session_key = Some(session_key);
        self.state = SessionState::AuthenticatingSrp;

        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let header = MacTelnetHeader::new(PacketType::Data, self.src_mac, self.dst_mac, self.session_id, seq);

        Ok((MacTelnetPacket::new(header, payload), session_key))
    }

    /// Step 3: Handle server proof M2
    pub fn handle_server_m2(&mut self, server_m2: &[u8; 32], server_pub_b: &[u8; 32]) -> Result<()> {
        if let (Some(srp), Some(k)) = (&self.srp_session, &self.derived_session_key) {
            srp.verify_server_m2(server_m2, server_pub_b, k)?;
            self.state = SessionState::Connected;
            info!("MAC-Telnet EC-SRP5 mutual authentication succeeded!");
            Ok(())
        } else {
            Err(anyhow!("No active SRP session state"))
        }
    }

    /// Send data packet (user keystrokes / terminal input)
    pub fn create_data_packet(&self, text_bytes: &[u8]) -> MacTelnetPacket {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let header = MacTelnetHeader::new(PacketType::Data, self.src_mac, self.dst_mac, self.session_id, seq);
        MacTelnetPacket::new(header, text_bytes.to_vec())
    }

    /// Disconnect session
    pub fn create_disconnect_packet(&mut self) -> MacTelnetPacket {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let header = MacTelnetHeader::new(PacketType::EndSession, self.src_mac, self.dst_mac, self.session_id, seq);
        self.state = SessionState::Terminating;
        MacTelnetPacket::new(header, Vec::new())
    }
}

pub struct MacTelnetServerEngine {
    pub local_mac: MacAddr,
    expected_username: String,
    expected_password: String,
}

impl MacTelnetServerEngine {
    pub fn new(local_mac: MacAddr, username: &str, password: &str) -> Self {
        Self {
            local_mac,
            expected_username: username.to_string(),
            expected_password: password.to_string(),
        }
    }

    /// Handle StartSession request and produce SRP challenge (Salt + Public B)
    pub fn handle_client_start(&self, client_pkt: &MacTelnetPacket) -> Result<(MacTelnetPacket, SrpServerSession)> {
        let srp_server = SrpServerSession::new(&self.expected_username, &self.expected_password);

        // Payload encodes: [SALT: 16 bytes | SERVER_PUB_B: 32 bytes]
        let mut challenge_payload = Vec::with_capacity(48);
        challenge_payload.extend_from_slice(&srp_server.salt);
        challenge_payload.extend_from_slice(&srp_server.server_public_b);

        let resp_header = MacTelnetHeader::new(
            PacketType::Data,
            self.local_mac,
            client_pkt.header.src_mac,
            client_pkt.header.session_id,
            1,
        );

        Ok((MacTelnetPacket::new(resp_header, challenge_payload), srp_server))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mactelnet_client_engine_lifecycle() {
        let src = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst = MacAddr([0x00, 0x0C, 0x42, 0xAA, 0xBB, 0xCC]);

        let mut client = MacTelnetClientEngine::new(src, dst, 4001, "admin", "admin123");
        assert_eq!(client.state, SessionState::Disconnected);

        let syn = client.create_start_session_packet();
        assert_eq!(syn.header.packet_type, PacketType::StartSession);
        assert_eq!(client.state, SessionState::Connecting);

        let server_engine = MacTelnetServerEngine::new(dst, "admin", "admin123");
        let (_challenge_pkt, server_srp) = server_engine.handle_client_start(&syn).unwrap();

        let (proof_pkt, client_k) = client
            .handle_challenge_and_generate_proof(&server_srp.salt, &server_srp.server_public_b)
            .unwrap();

        assert_eq!(client.state, SessionState::AuthenticatingSrp);
        assert_eq!(proof_pkt.payload.len(), 64);

        let client_pub_a: [u8; 32] = proof_pkt.payload[0..32].try_into().unwrap();
        let client_m1: [u8; 32] = proof_pkt.payload[32..64].try_into().unwrap();

        let (server_k, server_m2) = server_srp
            .verify_client_and_respond(&client_pub_a, &client_m1)
            .unwrap();

        assert_eq!(client_k, server_k);

        client
            .handle_server_m2(&server_m2, &server_srp.server_public_b)
            .unwrap();
        assert_eq!(client.state, SessionState::Connected);

        let data = client.create_data_packet(b"/ip address print\r\n");
        assert_eq!(data.header.packet_type, PacketType::Data);

        let fin = client.create_disconnect_packet();
        assert_eq!(fin.header.packet_type, PacketType::EndSession);
        assert_eq!(client.state, SessionState::Terminating);
    }
}
