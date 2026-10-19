use crate::error::ProtoError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    pub const ZERO: MacAddr = MacAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    #[inline]
    pub const fn new(bytes: [u8; 6]) -> Self {
        MacAddr(bytes)
    }

    #[inline]
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    #[inline]
    pub fn is_multicast(&self) -> bool {
        (self.0[0] & 0x01) != 0
    }

    #[inline]
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast() && !self.is_broadcast()
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({})", self)
    }
}

impl FromStr for MacAddr {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.trim();
        let parts: Vec<&str> = if clean.contains(':') {
            clean.split(':').collect()
        } else if clean.contains('-') {
            clean.split('-').collect()
        } else {
            return Err(ProtoError::InvalidMacAddress(s.to_string()));
        };

        if parts.len() != 6 {
            return Err(ProtoError::InvalidMacAddress(s.to_string()));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| ProtoError::InvalidMacAddress(s.to_string()))?;
        }

        Ok(MacAddr(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_parsing_and_formatting() {
        let mac_str = "00:0C:42:1F:2A:3B";
        let mac = MacAddr::from_str(mac_str).expect("Valid MAC");
        assert_eq!(mac.to_string(), mac_str);
        assert!(mac.is_unicast());
        assert!(!mac.is_broadcast());

        let bcast = MacAddr::from_str("FF:FF:FF:FF:FF:FF").unwrap();
        assert!(bcast.is_broadcast());

        let dash_format = MacAddr::from_str("00-0C-42-1F-2A-3B").unwrap();
        assert_eq!(dash_format, mac);
    }
}
