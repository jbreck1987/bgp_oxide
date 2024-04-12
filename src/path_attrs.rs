// This module will house all the structs and machinery related to Path Attributes (PA)

use std::{
    cell::RefCell,
    error::Error,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

// Implement a basic PA error
#[derive(Debug, PartialEq)]
struct PathAttrError(String);
impl Display for PathAttrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PathAttrError(msg) = self;
        write!(f, "{}", msg)
    }
}
impl Error for PathAttrError {}
// This Trait is necessary since the size of the data field for eath PA
// is variable. Will be used for creating a trait object for use in containers.
pub(crate) trait PAttr {
    // Bit Fiddling

    fn set_opt_bit(&mut self) {
        // Sets the appropriate bit to encode whether the PA is optional or not
        // RFC 4271; Pg. 16
    }
    fn set_trans_bit(&mut self) {
        // Sets the appropriate bit to encode whether the PA is transitive or not
        // RFC 4271; Pg. 17
    }
    fn set_partial_bit(&mut self) {
         // Sets the appropriate bit to encode whether the PA is Partial or not
         // RFC 4271; Pg. 17
    }
}

pub(crate) struct PathAttr {
    // Attribute Flags
    attr_flags: u8,
    // Attribute Type Code
    attr_type_code: u8,
    attr_len: u8,
    attr_value: Vec<u8>,
    
 }
impl PAttr for PathAttr {
    fn set_opt_bit(&mut self) {
        // Set MSB (network byte order) to 1
        self.attr_flags = self.attr_flags | 1 << 7;
    }
    fn set_trans_bit(&mut self) {
        // Set second MSB (network byte order) to 1
        self.attr_flags = self.attr_flags | 1 << 6;
    }
    fn set_partial_bit(&mut self) {
         // Set third MSB (network byte order) to 1
        self.attr_flags = self.attr_flags | 1 << 5;       
    }
}
enum AsSegment {
    // Used when building the AS_PATH PA. RFC 4721, Pg. 18
    // The vec holds ASes.
    AsSequence(Vec<u16>),
    AsSet(Vec<u16>)
}
impl PathAttr {
    fn new() -> Self {
        // Returns a bare PathAttr instance. This isn't public because all PAs should have
        // a function that builds them as opposed to manually creating them on the fly.
        // new() will only be used privately.
        Self {
            attr_flags: 0,
            attr_type_code: 0,
            attr_len: 0,
            attr_value: Vec::new(),
        }
    }
    pub(crate) fn build_origin(value: u8) -> Result<Self, PathAttrError> {
        // Builds the well-known, mandatory ORIGIN PA
        // RFC 4271; Pg. 18
        match value {
            0 | 1 | 2 => {
                // Build new PA instance
                let mut pa  = Self::new();
                pa.set_trans_bit();
                pa.attr_type_code = 1;
                pa.attr_len = 1;
                pa.attr_value.push(value);
                Ok(pa)
            }
            _ => {
                Err(PathAttrError(String::from("Invalid value, valid values are 0, 1, 2.")))
            }
        }
    }
    pub(crate) fn build_as_path(as_segs: Vec<AsSegment>) -> Self {
        // Builds the well-known, mandatory AS_PATH PA, RFC 4271, Pg. 18
        // This function assumes the given sequence of AS Segments has been constructed
        // properly.
        let mut pa = Self::new();
        pa.attr_type_code = 2;
        pa.set_trans_bit();

        // Now need to construct the attribute value as a sequence of AS Segments, each of which
        // are TLVs that will be flattened into a vec of u8s
        for seg in as_segs {
            match seg {
                AsSegment::AsSequence(ases) => {
                    // AS_SEQUENCE segment type is 2
                    pa.attr_value.push(2);
                    pa.attr_value.push(ases.len() as u8);
                    for a in ases {
                        // Decompose the u16 to two u8s and add to vec
                        pa.attr_value.extend_from_slice(a.to_be_bytes().as_slice());
                    }
                },
                AsSegment::AsSet(ases) => {
                    // AS_SET segment type is 1
                    pa.attr_value.push(1);
                    pa.attr_value.push(ases.len() as u8);
                    for a in ases {
                        // Decompose the u16 to two u8s and add to vec
                        pa.attr_value.extend_from_slice(a.to_be_bytes().as_slice());
                    }
                }
            }
        }
        pa.attr_len = pa.attr_value.len() as u8;
        pa
        
    }
    pub(crate) fn build_next_hop(next_hop: IpAddr) -> Self {
        // Builds the well-known, mandatory NEXT_HOP PA; RFC 4271, Pg. 19
        // Enabling both v4 and v6 transport
        let mut pa = Self::new();
        pa.set_trans_bit();
        pa.attr_type_code = 3;
        match next_hop {
            IpAddr::V4(inner_addr) => {
                pa.attr_len = 4;
                pa.attr_value.extend_from_slice(inner_addr.octets().as_slice())
            },
            IpAddr::V6(inner_addr) => {
                pa.attr_len = 16;
                pa.attr_value.extend_from_slice(inner_addr.octets().as_slice())
            }
        };
        pa
    }

    pub(crate) fn build_med(metric: u32) -> Self {
        // Builds the optional, non-transitory PA MULTI_EXIT_DISC (MED)
        // RFC 4271, Pg. 19
        let mut pa = Self::new();
        pa.set_opt_bit();
        pa.attr_type_code = 4;
        pa.attr_len = 4;

        // Need to decompose the u32 to bytes
        pa.attr_value.extend_from_slice(metric.to_be_bytes().as_slice());
        pa
    }

    pub(crate) fn build_local_pref(value: u32) -> Self {
        // Builds the well-known LOCAL_PREF PA
        // RFC 4271, Pg. 19
        let mut pa = Self::new();
        pa.set_trans_bit();
        pa.attr_type_code = 5;
        pa.attr_len = 4;
        pa.attr_value.extend_from_slice(value.to_be_bytes().as_slice());
        pa
    }
}

// Extended path attributes give 16 bits to determine the length of the attribute value (in octets)
pub(crate) struct PathAttrExt {
    // Attribute Flags
    attr_flags: u8,
    // Attribute Type Code
    attr_type_code: u8,
    attr_len: u16,
    attr_value: Vec<u8>,
 }
impl PAttr for PathAttrExt {}
impl PathAttrExt {
        fn set_ext_bit(&mut self) {
        // Sets the appropriate bits to encode an Extended Length PA
        // RFC 4271; Pg. 17
        todo!();
    }
}



#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;

    #[test]
    fn build_origin_valid_value() {
        for i in 0..=2 {
            let origin = PathAttr::build_origin(i);
            let cell = RefCell::new(origin);
            match cell.borrow().as_ref() {
                Ok(origin) => {
                    // Only transitive bit should be set since this is a well-known, mandatory (non-optional)
                    // PA. This means the attr flags field should equal 64 in decimal.
                    assert_eq!(64, origin.attr_flags);
                    assert_eq!(1, origin.attr_type_code);
                    assert_eq!(i, origin.attr_value[0]);
                }
                _ => {
                    println!("Expected Ok() for the given values, received and Err()")
                }

            };
        }
    }
    #[test]
    fn build_origin_invalid_value() {
        let origin = PathAttr::build_origin(11);
        let cell = RefCell::new(origin);
        match cell.borrow().as_ref() {
            Ok(_) => {
                panic!("Expected Err() due to incorrect value, got Ok()!")
            }
            Err(e) => {
                assert_eq!(*e, PathAttrError(String::from("Invalid value, valid values are 0, 1, 2.")));
            }
        };
    }
    #[test]
    fn build_as_path() {
        // Create a sequence of AS Segments. One AS_SET and one AS_SEQUENCE
        let as_segs = vec![AsSegment::AsSet(vec![65000u16, 65001]), AsSegment::AsSequence(vec![131u16, 30437])];
        let aspath = PathAttr::build_as_path(as_segs);
        let cell = RefCell::new(aspath);

        // Path Attr checks
        assert_eq!(cell.borrow().attr_flags, 64);
        assert_eq!(cell.borrow().attr_type_code, 2);
        assert_eq!(cell.borrow().attr_len, 12);
        // Verify the path attr values are correctly encoded.
        assert_eq!(cell.borrow().attr_value[0], 1); // AS_SET Segment type
        assert_eq!(cell.borrow().attr_value[1], 2); // num ASes in AS_SET
        assert_eq!(cell.borrow().attr_value[2], 253); // MSB of first AS
        assert_eq!(cell.borrow().attr_value[3], 232); // LSB of first AS
        assert_eq!(cell.borrow().attr_value[4], 253); // MSB of second AS
        assert_eq!(cell.borrow().attr_value[5], 233); // LSB of second AS
        assert_eq!(cell.borrow().attr_value[6], 2); // AS_SEQUENCE Segment type
        assert_eq!(cell.borrow().attr_value[7], 2); // num ASes in AS_SEQUENCE
        assert_eq!(cell.borrow().attr_value[8], 0); // MSB of first AS
        assert_eq!(cell.borrow().attr_value[9], 131); // LSB of first AS
        assert_eq!(cell.borrow().attr_value[10], 118); // MSB of second AS
        assert_eq!(cell.borrow().attr_value[11], 229); // LSB of second AS
    }
    #[test]
    fn build_next_hop_v4() {
        let ip = Ipv4Addr::from_str("192.168.0.0").unwrap();
        let n_hop = PathAttr::build_next_hop(IpAddr::V4(ip));
        let cell = RefCell::new(n_hop);

        // Path Attr checks
        assert_eq!(cell.borrow().attr_flags, 64u8);
        assert_eq!(cell.borrow().attr_type_code, 3u8);
        assert_eq!(cell.borrow().attr_len, 4u8);
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(cell.borrow().attr_value.as_slice());
        assert_eq!(Ipv4Addr::from(bytes), Ipv4Addr::from_str("192.168.0.0").unwrap());
    }
    #[test]
    fn build_next_hop_v6() {
        // Using Ipv6 Neighbor Solicitation dest address (multicast) because why not?
        let ip = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0x0001, 0xFFCC, 0xCCCC);
        let n_hop = PathAttr::build_next_hop(IpAddr::V6(ip));
        let cell = RefCell::new(n_hop);

        // Path Attr checks
        assert_eq!(cell.borrow().attr_flags, 64u8);
        assert_eq!(cell.borrow().attr_type_code, 3u8);
        assert_eq!(cell.borrow().attr_len, 16u8);

        // Cumbersome to build an Ipv6Addr, so will just compare the octets.
        assert_eq!(cell.borrow().attr_value, ip.octets());
    }
    #[test]
    fn build_med() {
        let med = PathAttr::build_med(1000);
        let cell = RefCell::new(med);

        // Path Attr checks
        assert_eq!(cell.borrow().attr_flags, 128);
        assert_eq!(cell.borrow().attr_type_code, 4);
        assert_eq!(cell.borrow().attr_len, 4);
        // Value check. Should be 1000 decomposed as a u32
        assert_eq!(cell.borrow().attr_value, vec![0u8, 0, 3, 232]);
    }
    #[test]
    fn build_local_pref() {
        let lp = PathAttr::build_local_pref(1000);
        let cell = RefCell::new(lp);

        // Path Attr checks
        assert_eq!(cell.borrow().attr_flags, 64);
        assert_eq!(cell.borrow().attr_type_code, 5);
        assert_eq!(cell.borrow().attr_len, 4);
        // Value check. Should be 1000 decomposed as a u32
        assert_eq!(cell.borrow().attr_value, vec![0u8, 0, 3, 232]);
    }
}