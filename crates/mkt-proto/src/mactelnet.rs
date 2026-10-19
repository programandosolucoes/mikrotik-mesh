use crate::error::ProtoError;
use crate::mac::MacAddr;
use byteorder::{BigEndian, ByteOrder};
use serde::{Deserialize, Serialize};

pub const MACTELNET_PORT: u16 = 20561;
pub const MACTELNET_HEADER_LEN: usize = 22;
pub const MACTELNET_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    Data = 0x00,
    StartSession = 0x01,
    Ack = 0x02,
    EndSession = 0x03,
    Ping = 0x04,
    PingReply = 0x05,
    Control = 0xFF,
}

impl PacketType {
    pub fn from_u8(val: u8) -> Result<Self, ProtoError> {
        match val {
            0x00 => Ok(PacketType::Data),
            0x01 => Ok(PacketType::StartSession),
            0x02 => Ok(PacketType::Ack),
            0x03 => Ok(PacketType::EndSession),
            0x04 => Ok(PacketType::Ping),
            0x05 => Ok(PacketType::PingReply),
            0xFF => Ok(PacketType::Control),
            other => Err(ProtoError::UnknownPacketType(other)),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacTelnetHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub session_id: u16,
    pub client_type: u16,
    pub sequence_number: u32,
}

impl MacTelnetHeader {
    pub fn new(
        packet_type: PacketType,
        src_mac: MacAddr,
        dst_mac: MacAddr,
        session_id: u16,
        sequence_number: u32,
    ) -> Self {
        Self {
            version: MACTELNET_VERSION,
            packet_type,
            src_mac,
            dst_mac,
            session_id,
            client_type: 0x0000,
            sequence_number,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < MACTELNET_HEADER_LEN {
            return Err(ProtoError::BufferTooSmall {
                required: MACTELNET_HEADER_LEN,
                available: buf.len(),
            });
        }

        let version = buf[0];
        if version != MACTELNET_VERSION {
            return Err(ProtoError::InvalidMacTelnetVersion(version));
        }

        let packet_type = PacketType::from_u8(buf[1])?;

        let mut src_bytes = [0u8; 6];
        src_bytes.copy_from_slice(&buf[2..8]);

        let mut dst_bytes = [0u8; 6];
        dst_bytes.copy_from_slice(&buf[8..14]);

        let session_id = BigEndian::read_u16(&buf[14..16]);
        let client_type = BigEndian::read_u16(&buf[16..18]);
        let sequence_number = BigEndian::read_u32(&buf[18..22]);

        Ok(Self {
            version,
            packet_type,
            src_mac: MacAddr(src_bytes),
            dst_mac: MacAddr(dst_bytes),
            session_id,
            client_type,
            sequence_number,
        })
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ProtoError> {
        if buf.len() < MACTELNET_HEADER_LEN {
            return Err(ProtoError::BufferTooSmall {
                required: MACTELNET_HEADER_LEN,
                available: buf.len(),
            });
        }

        buf[0] = self.version;
        buf[1] = self.packet_type.to_u8();
        buf[2..8].copy_from_slice(self.src_mac.as_bytes());
        buf[8..14].copy_from_slice(self.dst_mac.as_bytes());
        BigEndian::write_u16(&mut buf[14..16], self.session_id);
        BigEndian::write_u16(&mut buf[16..18], self.client_type);
        BigEndian::write_u32(&mut buf[18..22], self.sequence_number);

        Ok(MACTELNET_HEADER_LEN)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacTelnetPacket {
    pub header: MacTelnetHeader,
    pub payload: Vec<u8>,
}

impl MacTelnetPacket {
    pub fn new(header: MacTelnetHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    pub fn ack(src_mac: MacAddr, dst_mac: MacAddr, session_id: u16, seq: u32) -> Self {
        Self {
            header: MacTelnetHeader::new(PacketType::Ack, src_mac, dst_mac, session_id, seq),
            payload: Vec::new(),
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, ProtoError> {
        let header = MacTelnetHeader::parse(buf)?;
        let payload = buf[MACTELNET_HEADER_LEN..].to_vec();
        Ok(Self { header, payload })
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ProtoError> {
        let total_len = MACTELNET_HEADER_LEN + self.payload.len();
        if buf.len() < total_len {
            return Err(ProtoError::BufferTooSmall {
                required: total_len,
                available: buf.len(),
            });
        }

        self.header.serialize(&mut buf[..MACTELNET_HEADER_LEN])?;
        if !self.payload.is_empty() {
            buf[MACTELNET_HEADER_LEN..total_len].copy_from_slice(&self.payload);
        }

        Ok(total_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mactelnet_header_and_packet_roundtrip() {
        let src = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst = MacAddr([0x00, 0x0C, 0x42, 0xAA, 0xBB, 0xCC]);
        let header = MacTelnetHeader::new(PacketType::StartSession, src, dst, 0x4321, 1);

        let packet = MacTelnetPacket::new(header.clone(), b"terminal_params".to_vec());
        let mut buf = vec![0u8; 128];
        let written = packet.serialize(&mut buf).unwrap();

        assert_eq!(written, MACTELNET_HEADER_LEN + 15);

        let parsed = MacTelnetPacket::parse(&buf[..written]).unwrap();
        assert_eq!(parsed.header.version, 1);
        assert_eq!(parsed.header.packet_type, PacketType::StartSession);
        assert_eq!(parsed.header.src_mac, src);
        assert_eq!(parsed.header.dst_mac, dst);
        assert_eq!(parsed.header.session_id, 0x4321);
        assert_eq!(parsed.header.sequence_number, 1);
        assert_eq!(parsed.payload, b"terminal_params".to_vec());
    }

    #[test]
    fn test_ack_packet() {
        let src = MacAddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let dst = MacAddr([0x00, 0x06, 0x07, 0x08, 0x09, 0x0A]);
        let ack = MacTelnetPacket::ack(src, dst, 999, 42);

        let mut buf = [0u8; 32];
        let written = ack.serialize(&mut buf).unwrap();
        assert_eq!(written, MACTELNET_HEADER_LEN);

        let parsed = MacTelnetPacket::parse(&buf[..written]).unwrap();
        assert_eq!(parsed.header.packet_type, PacketType::Ack);
        assert_eq!(parsed.header.sequence_number, 42);
        assert!(parsed.payload.is_empty());
    }
}
