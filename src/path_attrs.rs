// This module will house all the structs and machinery related to Path Attributes (PA)

// TO-DOs: Use TypeState pattern to delineate between Normal and Extended Path Attributes.
// This way, we can get rid of dynamic dispatch (all will be the same size). Will be able to
// selectively serialize based off the State.

use std::{
    cell::RefCell,
    error::Error,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::message_types::{
    ByteLen,
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
// Also making this implement ByteLen for easing the building of Update messages.
pub(crate) trait PAttr: ByteLen {
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

enum AsSegment {
    // Used when building the AS_PATH PA. RFC 4721, Pg. 18
    // The vec holds ASes.
    AsSequence(Vec<u16>),
    AsSet(Vec<u16>)
}
////impl PathAttr {
//    fn new() -> Self {
//        // Returns a bare PathAttr instance. This isn't public because all PAs should have
//        // a function that builds them as opposed to manually creating them on the fly.
//        // new() will only be used privately.
//        Self {
//            attr_flags: 0,
//            attr_type_code: 0,
//            attr_len: 0,
//            attr_value: Vec::new(),
//        }
//    }
//    pub(crate) fn build_origin(value: u8) -> Result<Self, PathAttrError> {
//        // Builds the well-known, mandatory ORIGIN PA
//        // RFC 4271; Pg. 18
//        match value {
//            0 | 1 | 2 => {
//                // Build new PA instance
//                let mut pa  = Self::new();
//                pa.set_trans_bit();
//                pa.attr_type_code = 1;
//                pa.attr_len = 1;
//                pa.attr_value.push(value);
//                Ok(pa)
//            }
//            _ => {
//                Err(PathAttrError(String::from("Invalid value, valid values are 0, 1, 2.")))
//            }
//        }
//    }
//    pub(crate) fn build_as_path(as_segs: Vec<AsSegment>) -> Self {
//        // Builds the well-known, mandatory AS_PATH PA, RFC 4271, Pg. 18
//        // This function assumes the given sequence of AS Segments has been constructed
//        // properly.
//        let mut pa = Self::new();
//        pa.attr_type_code = 2;
//        pa.set_trans_bit();
//
//        // Now need to construct the attribute value as a sequence of AS Segments, each of which
//        // are TLVs that will be flattened into a vec of u8s
//        for seg in as_segs {
//            match seg {
//                AsSegment::AsSequence(ases) => {
//                    // AS_SEQUENCE segment type is 2
//                    pa.attr_value.push(2);
//                    pa.attr_value.push(ases.len() as u8);
//                    for a in ases {
//                        // Decompose the u16 to two u8s and add to vec
//                        pa.attr_value.extend_from_slice(a.to_be_bytes().as_slice());
//                    }
//                },
//                AsSegment::AsSet(ases) => {
//                    // AS_SET segment type is 1
//                    pa.attr_value.push(1);
//                    pa.attr_value.push(ases.len() as u8);
//                    for a in ases {
//                        // Decompose the u16 to two u8s and add to vec
//                        pa.attr_value.extend_from_slice(a.to_be_bytes().as_slice());
//                    }
//                }
//            }
//        }
//        pa.attr_len = pa.attr_value.len() as u8;
//        pa
//        
//    }
//    pub(crate) fn build_next_hop(next_hop: IpAddr) -> Self {
//        // Builds the well-known, mandatory NEXT_HOP PA; RFC 4271, Pg. 19
//        // Enabling both v4 and v6 transport
//        let mut pa = Self::new();
//        pa.set_trans_bit();
//        pa.attr_type_code = 3;
//        match next_hop {
//            IpAddr::V4(inner_addr) => {
//                pa.attr_len = 4;
//                pa.attr_value.extend_from_slice(inner_addr.octets().as_slice())
//            },
//            IpAddr::V6(inner_addr) => {
//                pa.attr_len = 16;
//                pa.attr_value.extend_from_slice(inner_addr.octets().as_slice())
//            }
//        };
//        pa
//    }
//
//    pub(crate) fn build_med(metric: u32) -> Self {
//        // Builds the optional, non-transitory PA MULTI_EXIT_DISC (MED)
//        // RFC 4271, Pg. 19
//        let mut pa = Self::new();
//        pa.set_opt_bit();
//        pa.attr_type_code = 4;
//        pa.attr_len = 4;
//
//        // Need to decompose the u32 to bytes
//        pa.attr_value.extend_from_slice(metric.to_be_bytes().as_slice());
//        pa
//    }
//
//    pub(crate) fn build_local_pref(value: u32) -> Self {
//        // Builds the well-known LOCAL_PREF PA
//        // RFC 4271, Pg. 19
//        let mut pa = Self::new();
//        pa.set_trans_bit();
//        pa.attr_type_code = 5;
//        pa.attr_len = 4;
//        pa.attr_value.extend_from_slice(value.to_be_bytes().as_slice());
//        pa
//    }
//
//    pub(crate) fn build_atomic_agg() -> Self {
//        // Builds the well-known, discretionary ATOMIC_AGGREGATE PA
//        // RFC 4271, Pg. 19. This is essentially a marker PA.
//        let mut pa = Self::new();
//        pa.set_trans_bit();
//        pa.attr_type_code = 6;
//        pa.attr_len = 0;
//        pa
//    }
//    pub(crate) fn build_aggregator_v4(last_as: u16, speaker: Ipv4Addr) -> Self {
//        // Builds the optional, transitive AGGREGATOR PA.
//        // RFC 4271, Pg. 19. Note that the base RFC only allows for BGP speakers
//        // to use IPv4 addresses as IDs!
//        let mut pa = Self::new();
//        pa.set_trans_bit();
//        pa.set_opt_bit();
//        pa.attr_type_code = 7;
//        pa.attr_len = 6;
//        // Append Last AS
//        pa.attr_value.extend_from_slice(last_as.to_be_bytes().as_slice());
//        // Append ID of the aggregator
//        pa.attr_value.extend_from_slice(speaker.octets().as_slice());
//        pa
//    }
//}

// Implement the base PathAttr Type, along with its States (marker structs).
// The marker structs are used to flag whether the PA is Standard or Extended.
pub(crate) struct PaStd;
pub(crate) struct PaExt;
pub(crate) struct PathAttr<T> {
    state: T,
    // Attribute Flags
    attr_flags: u8,
    // Attribute Type Code
    attr_type_code: u8,
    // Attribute Length; All PAs will have a u16 for the length.
    // the state will determine how this is parsed and serialized (as u8 or u16)
    attr_len: u16,
    attr_value: Vec<u8>,
}
// Both states will implement these methods the same
impl<T> PAttr for PathAttr<T> {
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
// Both states will implement these methods the same.
impl<T> PathAttr<T> {
    pub fn attr_type_code(&self) -> u8 {
        self.attr_type_code
    }
    pub fn attr_flags(&self) -> u8 {
        self.attr_flags
    }
    pub fn attr_value(&self) -> &[u8] {
        self.attr_value.as_slice()
    }
}
// Will have unique new() methods for PaExt and PaStd impls
// since we want to restrict the user to only using u8's for
// the attr_len for PaStd and u16's for PaExt. Will also use
// custom attr_len getters for each type to enforce this on 
// read.
impl<PaExt> PathAttr<PaExt> {
    pub fn new(attr_type_code: u8,
               attr_len: u16,
               attr_value: &[u8]) -> Self {
            
        Self { 
               state: PaExt,
               // Setting the extended bit
               attr_flags: 0 | 1 << 4,
               attr_type_code,
               attr_len,
               attr_value
             }
    }
    pub fn attr_len(&self) -> u16 {
        self.attr_len
    }
}

impl<PaStd> PathAttr<PaStd> {
    pub fn new(attr_type_code: u8,
               attr_len: u8,
               attr_value: &[u8]) -> Self {
            
        Self { 
               state: PaStd,
               // Unsetting the extended bit
               attr_flags: 0,
               attr_type_code,
               attr_len: attr_len as u16,
               attr_value
             }
    }
    pub fn attr_len(&self) -> u8 {
        self.attr_len as u8
    }
}

pub(crate) trait PaBuilder<T> {
    fn build() -> PathAttr<T>;
}

pub(crate) struct Origin;
impl PaBuilder<PaStd> for Origin {
    fn build(mut self, origin_val: u8) -> PathAttr<PaStd> {
        let mut pa: PathAttr<PaStd> = PathAttr::new(
            1,
            1,
            vec![origin_val].as_slice(),
        );
        pa.set_trans_bit();
        pa
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
        // Value check. Should be 1000 decomposed as a u8
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
        // Value check. Should be 1000 decomposed as a u8
        assert_eq!(cell.borrow().attr_value, vec![0u8, 0, 3, 232]);
    }
    #[test]
    fn build_atomic_agg() {
        let aa = PathAttr::build_atomic_agg();
        let cell = RefCell::new(aa);

        // Path Attr checks
        assert_eq!(cell.borrow().attr_flags, 64);
        assert_eq!(cell.borrow().attr_type_code, 6);
        assert_eq!(cell.borrow().attr_len, 0);
        // Value check. Should be 1000 decomposed as a u8
        assert_eq!(cell.borrow().attr_value.is_empty(), true);
        assert_eq!(cell.borrow().attr_value.len(), 0);
    }
    #[test]
    fn build_aggregator_v4() {
        let ag = PathAttr::build_aggregator_v4(65000, Ipv4Addr::new(1, 1, 1, 1));
        let cell = RefCell::new(ag);

        // Path Attr checks
        assert_eq!(cell.borrow().attr_flags, 192);
        assert_eq!(cell.borrow().attr_type_code, 7);
        assert_eq!(cell.borrow().attr_len, 6);
        
        // First get the appropriate bytes from the vec as u8 arrays
        let mut last_as_bytes: [u8; 2] = [0u8; 2];
        let mut ip_bytes: [u8; 4] = [0u8; 4];
        last_as_bytes.copy_from_slice(cell.borrow().attr_value[0..=1].as_ref());
        ip_bytes.copy_from_slice(cell.borrow().attr_value[2..=5].as_ref());

        // Now can check to see if they are correct.
        assert_eq!(u16::from_be_bytes(last_as_bytes), 65000u16);
        assert_eq!(Ipv4Addr::from(ip_bytes), Ipv4Addr::new(1, 1, 1, 1));
    }
}