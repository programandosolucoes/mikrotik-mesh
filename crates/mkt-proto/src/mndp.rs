use crate::error::ProtoError;
use crate::mac::MacAddr;
use byteorder::{BigEndian, ByteOrder};
use serde::{Deserialize, Serialize};

pub const MNDP_PORT: u16 = 5678;

pub const TLV_MAC_ADDRESS: u16 = 0x0001;
pub const TLV_IDENTITY: u16 = 0x0005;
pub const TLV_VERSION: u16 = 0x0007;
pub const TLV_PLATFORM: u16 = 0x0008;
pub const TLV_UPTIME: u16 = 0x000A;
pub const TLV_SOFTWARE_ID: u16 = 0x000B;
pub const TLV_BOARD_NAME: u16 = 0x000C;
pub const TLV_INTERFACE_NAME: u16 = 0x0010;
pub const TLV_IPV4: u16 = 0x0011;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MndpMessage {
    pub mac: Option<MacAddr>,
    pub identity: Option<String>,
    pub version: Option<String>,
    pub platform: Option<String>,
    pub uptime_secs: Option<u32>,
    pub software_id: Option<String>,
    pub board_name: Option<String>,
    pub interface_name: Option<String>,
    pub ipv4: Option<std::net::Ipv4Addr>,
}

impl MndpMessage {
    pub fn parse(buf: &[u8]) -> Result<Self, ProtoError> {
        // MNDP packets usually have a 4-byte header (seq/reserved) followed by TLVs
        if buf.len() < 4 {
            return Err(ProtoError::BufferTooSmall {
                required: 4,
                available: buf.len(),
            });
        }

        let mut msg = MndpMessage::default();
        let mut offset = 4;

        while offset + 4 <= buf.len() {
            let tlv_type = BigEndian::read_u16(&buf[offset..offset + 2]);
            let tlv_len = BigEndian::read_u16(&buf[offset + 2..offset + 4]) as usize;
            offset += 4;

            if offset + tlv_len > buf.len() {
                return Err(ProtoError::InvalidMndpTlv);
            }

            let val_slice = &buf[offset..offset + tlv_len];
            offset += tlv_len;

            match tlv_type {
                TLV_MAC_ADDRESS if tlv_len == 6 => {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(val_slice);
                    msg.mac = Some(MacAddr(mac));
                }
                TLV_IDENTITY => {
                    msg.identity = Some(String::from_utf8_lossy(val_slice).to_string());
                }
                TLV_VERSION => {
                    msg.version = Some(String::from_utf8_lossy(val_slice).to_string());
                }
                TLV_PLATFORM => {
                    msg.platform = Some(String::from_utf8_lossy(val_slice).to_string());
                }
                TLV_UPTIME if tlv_len == 4 => {
                    msg.uptime_secs = Some(BigEndian::read_u32(val_slice));
                }
                TLV_SOFTWARE_ID => {
                    msg.software_id = Some(String::from_utf8_lossy(val_slice).to_string());
                }
                TLV_BOARD_NAME => {
                    msg.board_name = Some(String::from_utf8_lossy(val_slice).to_string());
                }
                TLV_INTERFACE_NAME => {
                    msg.interface_name = Some(String::from_utf8_lossy(val_slice).to_string());
                }
                TLV_IPV4 if tlv_len == 4 => {
                    msg.ipv4 = Some(std::net::Ipv4Addr::new(
                        val_slice[0],
                        val_slice[1],
                        val_slice[2],
                        val_slice[3],
                    ));
                }
                _ => {
                    // Ignore unknown TLVs gracefully
                }
            }
        }

        Ok(msg)
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ProtoError> {
        if buf.len() < 4 {
            return Err(ProtoError::BufferTooSmall {
                required: 4,
                available: buf.len(),
            });
        }

        // Write 4-byte MNDP header (zeros for seq/reserved)
        buf[0..4].fill(0);
        let mut offset = 4;

        let write_tlv = |buf: &mut [u8], offset: &mut usize, tlv_type: u16, val: &[u8]| -> Result<(), ProtoError> {
            let needed = 4 + val.len();
            if *offset + needed > buf.len() {
                return Err(ProtoError::BufferTooSmall {
                    required: *offset + needed,
                    available: buf.len(),
                });
            }
            BigEndian::write_u16(&mut buf[*offset..*offset + 2], tlv_type);
            BigEndian::write_u16(&mut buf[*offset + 2..*offset + 4], val.len() as u16);
            *offset += 4;
            buf[*offset..*offset + val.len()].copy_from_slice(val);
            *offset += val.len();
            Ok(())
        };

        if let Some(mac) = &self.mac {
            write_tlv(buf, &mut offset, TLV_MAC_ADDRESS, mac.as_bytes())?;
        }
        if let Some(identity) = &self.identity {
            write_tlv(buf, &mut offset, TLV_IDENTITY, identity.as_bytes())?;
        }
        if let Some(version) = &self.version {
            write_tlv(buf, &mut offset, TLV_VERSION, version.as_bytes())?;
        }
        if let Some(platform) = &self.platform {
            write_tlv(buf, &mut offset, TLV_PLATFORM, platform.as_bytes())?;
        }
        if let Some(uptime) = self.uptime_secs {
            let mut uptime_bytes = [0u8; 4];
            BigEndian::write_u32(&mut uptime_bytes, uptime);
            write_tlv(buf, &mut offset, TLV_UPTIME, &uptime_bytes)?;
        }
        if let Some(board) = &self.board_name {
            write_tlv(buf, &mut offset, TLV_BOARD_NAME, board.as_bytes())?;
        }
        if let Some(iface) = &self.interface_name {
            write_tlv(buf, &mut offset, TLV_INTERFACE_NAME, iface.as_bytes())?;
        }
        if let Some(ipv4) = &self.ipv4 {
            write_tlv(buf, &mut offset, TLV_IPV4, &ipv4.octets())?;
        }

        Ok(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mndp_message_roundtrip() {
        let msg = MndpMessage {
            mac: Some(MacAddr([0x00, 0x0c, 0x42, 0x11, 0x22, 0x33])),
            identity: Some("CHR-Router-01".to_string()),
            version: Some("7.16".to_string()),
            platform: Some("MikroTik".to_string()),
            uptime_secs: Some(3600),
            software_id: None,
            board_name: Some("x86_64".to_string()),
            interface_name: Some("ether1".to_string()),
            ipv4: Some(std::net::Ipv4Addr::new(192, 168, 88, 1)),
        };

        let mut buf = vec![0u8; 256];
        let written = msg.serialize(&mut buf).unwrap();

        let parsed = MndpMessage::parse(&buf[..written]).unwrap();
        assert_eq!(msg, parsed);
    }
}
