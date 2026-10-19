use crate::error::ProtoError;
use crate::mac::MacAddr;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

pub const EOIP_GRE_FLAGS_VER: u16 = 0x2001; // GRE Version 1 + Key Flag
pub const EOIP_PROTO_TYPE: u16 = 0x6400;    // MikroTik EoIP EtherType
pub const EOIP_HEADER_LEN: usize = 8;
pub const ETH_HEADER_LEN: usize = 14;
pub const MAX_SAFE_ETHERNET_FRAME: usize = 1518;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EoipHeader {
    pub flags_version: u16,
    pub proto_type: u16,
    pub frame_length: u16, // Big Endian on wire
    pub tunnel_id: u16,    // Little Endian on wire
}

impl EoipHeader {
    pub fn new(tunnel_id: u16, frame_length: u16) -> Self {
        Self {
            flags_version: EOIP_GRE_FLAGS_VER,
            proto_type: EOIP_PROTO_TYPE,
            frame_length,
            tunnel_id,
        }
    }

    pub fn keepalive(tunnel_id: u16) -> Self {
        Self::new(tunnel_id, 0)
    }

    pub fn is_keepalive(&self) -> bool {
        self.frame_length == 0
    }

    pub fn parse(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < EOIP_HEADER_LEN {
            return Err(ProtoError::BufferTooSmall {
                required: EOIP_HEADER_LEN,
                available: buf.len(),
            });
        }

        let flags_version = BigEndian::read_u16(&buf[0..2]);
        if flags_version != EOIP_GRE_FLAGS_VER {
            return Err(ProtoError::InvalidEoipFlags(flags_version));
        }

        let proto_type = BigEndian::read_u16(&buf[2..4]);
        if proto_type != EOIP_PROTO_TYPE {
            return Err(ProtoError::InvalidEoipProtocol(proto_type));
        }

        let frame_length = BigEndian::read_u16(&buf[4..6]);
        let tunnel_id = LittleEndian::read_u16(&buf[6..8]); // MikroTik quirk: Little Endian

        Ok(Self {
            flags_version,
            proto_type,
            frame_length,
            tunnel_id,
        })
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ProtoError> {
        if buf.len() < EOIP_HEADER_LEN {
            return Err(ProtoError::BufferTooSmall {
                required: EOIP_HEADER_LEN,
                available: buf.len(),
            });
        }

        BigEndian::write_u16(&mut buf[0..2], self.flags_version);
        BigEndian::write_u16(&mut buf[2..4], self.proto_type);
        BigEndian::write_u16(&mut buf[4..6], self.frame_length);
        LittleEndian::write_u16(&mut buf[6..8], self.tunnel_id);

        Ok(EOIP_HEADER_LEN)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthernetFrame {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    pub fn parse(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < ETH_HEADER_LEN {
            return Err(ProtoError::BufferTooSmall {
                required: ETH_HEADER_LEN,
                available: buf.len(),
            });
        }

        let mut dst = [0u8; 6];
        dst.copy_from_slice(&buf[0..6]);

        let mut src = [0u8; 6];
        src.copy_from_slice(&buf[6..12]);

        let ethertype = BigEndian::read_u16(&buf[12..14]);
        let payload = buf[14..].to_vec();

        Ok(Self {
            dst_mac: MacAddr(dst),
            src_mac: MacAddr(src),
            ethertype,
            payload,
        })
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ProtoError> {
        let total_len = ETH_HEADER_LEN + self.payload.len();
        if buf.len() < total_len {
            return Err(ProtoError::BufferTooSmall {
                required: total_len,
                available: buf.len(),
            });
        }

        buf[0..6].copy_from_slice(self.dst_mac.as_bytes());
        buf[6..12].copy_from_slice(self.src_mac.as_bytes());
        BigEndian::write_u16(&mut buf[12..14], self.ethertype);
        buf[14..total_len].copy_from_slice(&self.payload);

        Ok(total_len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EoipPacket {
    pub header: EoipHeader,
    pub ethernet_frame_raw: Vec<u8>,
}

impl EoipPacket {
    pub fn new(tunnel_id: u16, frame: Vec<u8>) -> Result<Self, ProtoError> {
        if frame.len() > MAX_SAFE_ETHERNET_FRAME {
            return Err(ProtoError::PayloadExceedsMtu(frame.len()));
        }

        let header = EoipHeader::new(tunnel_id, frame.len() as u16);
        Ok(Self {
            header,
            ethernet_frame_raw: frame,
        })
    }

    pub fn keepalive(tunnel_id: u16) -> Self {
        Self {
            header: EoipHeader::keepalive(tunnel_id),
            ethernet_frame_raw: Vec::new(),
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, ProtoError> {
        let header = EoipHeader::parse(buf)?;
        let declared_len = header.frame_length as usize;
        let available_payload = buf.len() - EOIP_HEADER_LEN;

        if header.is_keepalive() {
            return Ok(Self {
                header,
                ethernet_frame_raw: Vec::new(),
            });
        }

        if available_payload < declared_len {
            return Err(ProtoError::EoipLengthMismatch {
                declared: declared_len,
                actual: available_payload,
            });
        }

        // Slice exactly the declared frame length (resilient to trailing padding)
        let frame = buf[EOIP_HEADER_LEN..EOIP_HEADER_LEN + declared_len].to_vec();

        Ok(Self {
            header,
            ethernet_frame_raw: frame,
        })
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ProtoError> {
        let total_len = EOIP_HEADER_LEN + self.ethernet_frame_raw.len();
        if buf.len() < total_len {
            return Err(ProtoError::BufferTooSmall {
                required: total_len,
                available: buf.len(),
            });
        }

        self.header.serialize(&mut buf[..EOIP_HEADER_LEN])?;
        if !self.ethernet_frame_raw.is_empty() {
            buf[EOIP_HEADER_LEN..total_len].copy_from_slice(&self.ethernet_frame_raw);
        }

        Ok(total_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eoip_header_roundtrip() {
        let header = EoipHeader::new(1050, 64);
        let mut buf = [0u8; 8];
        header.serialize(&mut buf).unwrap();

        assert_eq!(&buf[0..2], &[0x20, 0x01]);
        assert_eq!(&buf[2..4], &[0x64, 0x00]);
        assert_eq!(&buf[4..6], &[0x00, 0x40]); // 64 big endian
        assert_eq!(&buf[6..8], &[0x1a, 0x04]); // 1050 little endian (0x041a)

        let parsed = EoipHeader::parse(&buf).unwrap();
        assert_eq!(header, parsed);
        assert!(!parsed.is_keepalive());
    }

    #[test]
    fn test_eoip_keepalive() {
        let keepalive = EoipPacket::keepalive(500);
        let mut buf = [0u8; 8];
        let written = keepalive.serialize(&mut buf).unwrap();
        assert_eq!(written, 8);

        let parsed = EoipPacket::parse(&buf).unwrap();
        assert!(parsed.header.is_keepalive());
        assert_eq!(parsed.header.tunnel_id, 500);
        assert!(parsed.ethernet_frame_raw.is_empty());
    }

    #[test]
    fn test_eoip_packet_with_ethernet_payload() {
        let dummy_eth = vec![0x00, 0x0c, 0x42, 0x01, 0x02, 0x03, // dst
                             0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
                             0x08, 0x00,                         // IPv4
                             0xde, 0xad, 0xbe, 0xef];            // payload

        let packet = EoipPacket::new(1234, dummy_eth.clone()).unwrap();
        let mut buf = vec![0u8; 100];
        let bytes_written = packet.serialize(&mut buf).unwrap();

        assert_eq!(bytes_written, 8 + dummy_eth.len());
        let parsed = EoipPacket::parse(&buf[..bytes_written]).unwrap();
        assert_eq!(parsed.header.tunnel_id, 1234);
        assert_eq!(parsed.ethernet_frame_raw, dummy_eth);

        let eth = EthernetFrame::parse(&parsed.ethernet_frame_raw).unwrap();
        assert_eq!(eth.dst_mac.to_string(), "00:0C:42:01:02:03");
        assert_eq!(eth.ethertype, 0x0800);
        assert_eq!(eth.payload, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
