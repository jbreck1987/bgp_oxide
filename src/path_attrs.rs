// This module will house all the structs and machinery related to Path Attributes (PA)

// TO-DOs: Use TypeState pattern to delineate between Normal and Extended Path Attributes.
// This way, we can get rid of dynamic dispatch (all will be the same size). Will be able to
// selectively serialize based off the State.

use std::{
    error::Error,
    fmt::Display,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::message_types::ByteLen;


// ** CONSTANTS **
pub (crate) const ORIGIN: u8 = 1;
pub (crate) const AS_PATH: u8 = 2;
pub (crate) const NEXT_HOP: u8 = 3;
pub (crate) const MED: u8 = 4;
pub (crate) const LOCAL_PREF: u8 = 5;
pub (crate) const ATOMIC_AGGREGATE: u8 = 6;
pub (crate) const AGGREGATOR: u8 = 7;

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
// May not need this trait since not using dynamic dispatch anymore. Functionality
// can just be moved into the impl.
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

// Enum to flag whether a PA is Standard or Extended
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PathAttrLen {
    Std(u8),
    Ext(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PathAttr {
    // Attribute Flags
    attr_flags: u8,
    // Attribute Type Code
    attr_type_code: u8,
    // Attribute Length; All PAs will have a u16 for the length.
    attr_len: PathAttrLen,
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
impl PathAttr {
    pub fn new(
        attr_type_code: u8,
        attr_len: PathAttrLen,
        attr_value: Vec<u8>) -> Self {
            Self {
                attr_flags: 0,
                attr_type_code,
                attr_len,
                attr_value
            }
    }
    pub fn attr_type_code(&self) -> u8 {
        self.attr_type_code
    }
    pub fn attr_flags(&self) -> u8 {
        self.attr_flags
    }
    pub fn attr_len(&self) -> &PathAttrLen {
        &self.attr_len
    }
    pub fn attr_value(&self) -> &[u8] {
        self.attr_value.as_slice()
    }
}
impl ByteLen for PathAttr {
   fn byte_len(&self) -> usize {
        let attr_len: usize = match self.attr_len {
            PathAttrLen::Std(_) => 1,
            PathAttrLen::Ext(_) => 2,
        };
        2 + attr_len + self.attr_value.len()
   }
}

// This trait will enforce that all impls for custom Path Attributes
// have a build method that returns a structurally valid PA type. This
// should greatly simplify the API.
pub(crate) trait PaBuilder {
    fn build(self) -> PathAttr;
}
// This is a generic builder that can be used over any custom Path Attribute type.
// May add a trait bound later that requires that requires each impl to have a build()
// method.
pub(crate) struct PathAttrBuilder<T> {
    _marker: PhantomData<T>,
    attr_type_code: u8,
    attr_len: PathAttrLen,
    attr_value: Vec<u8>,
}

impl<T> PathAttrBuilder<T> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
            attr_type_code: 0,
            attr_len: PathAttrLen::Std(0),
            attr_value: Vec::new()
        }
    }
}

// ** Individual Path Attribute Definitions for those defined in RFC4271 **

// ** ORIGIN **
pub(crate) struct Origin;

#[derive(Debug, Clone)]
pub(crate) enum OriginValue {
    Igp,
    Egp,
    Incomplete
}

impl From<OriginValue> for u8 {
    fn from(value: OriginValue) -> Self {
        match value {
            OriginValue::Igp => 0,
            OriginValue::Egp => 1,
            OriginValue::Incomplete => 2
        }   
    }
}

impl PathAttrBuilder<Origin> {
    pub fn origin(mut self, val: OriginValue) -> Self {
        self.attr_value.push(val.into());
        self
    }
}

impl PaBuilder for PathAttrBuilder<Origin> {
    fn build(self) -> PathAttr {
        let mut pa = PathAttr::new(
            1,
            PathAttrLen::Std(1),
            self.attr_value
        );
        pa.set_trans_bit();
        pa
    }
}

// ** AS_PATH **

pub(crate) struct AsPath;
enum AsSegment {
    // Used when building the AS_PATH PA. RFC 4721, Pg. 18
    // The vec holds ASes.
    AsSequence(Vec<u16>),
    AsSet(Vec<u16>)
}

impl PathAttrBuilder<AsPath> {
    pub fn as_segments(mut self, val: Vec<AsSegment>) -> Self {
        // Need to decompose the Vec<AsSegments> into a Vec<u8> to conform
        // to standard and store in local vec.
        // TO-DO: Try to use functional style here
        self.attr_value = Vec::new();
        for seg in val {
            match seg {
                AsSegment::AsSequence(ases) => {
                    // AS_SEQUENCE segment type is 2
                    self.attr_value.push(2);
                    self.attr_value.push(ases.len() as u8);
                    for a in ases {
                        // Decompose the u16 to two u8s and add to vec
                        self.attr_value.extend_from_slice(a.to_be_bytes().as_slice());
                    }
                },
                AsSegment::AsSet(ases) => {
                    // AS_SET segment type is 1
                    self.attr_value.push(1);
                    self.attr_value.push(ases.len() as u8);
                    for a in ases {
                        // Decompose the u16 to two u8s and add to vec
                        self.attr_value.extend_from_slice(a.to_be_bytes().as_slice());
                    }
                }
            }
        }
        self
    }
}

impl PaBuilder for PathAttrBuilder<AsPath> {
    fn build(self) -> PathAttr {
        let mut pa = PathAttr::new(
            2,
            PathAttrLen::Std(self.attr_value.len() as u8),
            self.attr_value
        );
        pa.set_trans_bit();
        pa
    }
}

// ** NEXT_HOP **

pub(crate) struct NextHop;

impl PathAttrBuilder<NextHop> {
    pub fn next_hop(mut self, val: IpAddr) -> Self {
        match val {
            IpAddr::V4(inner_addr) => {
                self.attr_len = PathAttrLen::Std(4);
                self.attr_value.extend_from_slice(inner_addr.octets().as_slice())
            },
            IpAddr::V6(inner_addr) => {
                self.attr_len = PathAttrLen::Std(16);
                self.attr_value.extend_from_slice(inner_addr.octets().as_slice())
            }
        }
        self
    }
}

impl PaBuilder for PathAttrBuilder<NextHop> {
    fn build(self) -> PathAttr {
        let mut pa = PathAttr::new(
            3,
            self.attr_len,
            self.attr_value);
        pa.set_trans_bit();
        pa
    }
}

// ** MED **

pub(crate) struct Med;
impl PathAttrBuilder<Med> {
    pub fn metric(mut self, val: u32) -> Self {
        // Builds the optional, non-transitory PA MULTI_EXIT_DISC (MED)
        // RFC 4271, Pg. 19

        // Decompose the u32 into bytes per spec
        self.attr_value.extend_from_slice(val.to_be_bytes().as_slice());
        self
    }
}
impl PaBuilder for PathAttrBuilder<Med> {
    fn build(self) -> PathAttr {
        let mut pa = PathAttr::new(
            4,
            PathAttrLen::Std(4),
            self.attr_value);
        pa.set_opt_bit();
        pa
    }
    
}

// ** LOCAL_PREF **

pub(crate) struct LocalPref;
impl PathAttrBuilder<LocalPref> {
    pub fn local_pref(mut self, val: u32) -> Self {
        self.attr_value.extend_from_slice(val.to_be_bytes().as_slice());
        self
    }
}

impl PaBuilder for PathAttrBuilder<LocalPref> {
    fn build(self) -> PathAttr {
        let mut pa = PathAttr::new(
            5,
            PathAttrLen::Std(4),
            self.attr_value);
        pa.set_trans_bit();
        pa
    }
    
}

// ** ATOMIC_AGGREGATE **

pub(crate) struct AtomicAggregate;
impl PaBuilder for PathAttrBuilder<AtomicAggregate> {
    fn build(self) -> PathAttr {
        // Builds the well-known, discretionary ATOMIC_AGGREGATE PA
        // RFC 4271, Pg. 19. This is essentially a marker PA.
        let mut pa = PathAttr::new(
            6,
            PathAttrLen::Std(0),
            self.attr_value);
        pa.set_trans_bit();
        pa
    }
}


// ** AGGREGATOR **
pub(crate) struct Aggregator;
impl PathAttrBuilder<Aggregator> {
    pub fn aggregator(mut self, last_as: u16, speaker: Ipv4Addr) -> Self {
        // Append Last AS
        self.attr_value.extend_from_slice(last_as.to_be_bytes().as_slice());
        // Append ID of the aggregator
        self.attr_value.extend_from_slice(speaker.octets().as_slice());
        self
    }
}
impl PaBuilder for PathAttrBuilder<Aggregator> {
    fn build(self) -> PathAttr {
        let mut pa = PathAttr::new(
            7,
            PathAttrLen::Std(6),
            self.attr_value);
        pa.set_trans_bit();
        pa.set_opt_bit();
        pa
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_origin() {
        let variants = vec![OriginValue::Igp, OriginValue::Egp, OriginValue::Incomplete];
        for (idx, v) in variants.into_iter().enumerate() {
            let origin = PathAttrBuilder::<Origin>::new().origin(v).build();
            assert_eq!(64, origin.attr_flags);
            assert_eq!(1, origin.attr_type_code);
            assert_eq!(PathAttrLen::Std(1), origin.attr_len);
            assert_eq!(idx as u8, origin.attr_value[0]);
        }
    }

    #[test]
    fn build_as_path() {
        // Create a sequence of AS Segments. One AS_SET and one AS_SEQUENCE
        let as_segs = vec![AsSegment::AsSet(vec![65000u16, 65001]), AsSegment::AsSequence(vec![131u16, 30437])];
        let aspath = PathAttrBuilder::<AsPath>::new().as_segments(as_segs).build();

        // Verify the path attr values are correctly encoded.
        // Path Attr checks
        assert_eq!(aspath.attr_flags, 64);
        assert_eq!(aspath.attr_type_code, 2);
        assert_eq!(aspath.attr_len, PathAttrLen::Std(12));
        assert_eq!(aspath.attr_value[0], 1); // AS_SET Segment type
        assert_eq!(aspath.attr_value[1], 2); // num ASes in AS_SET
        assert_eq!(aspath.attr_value[2], 253); // MSB of first AS
        assert_eq!(aspath.attr_value[3], 232); // LSB of first AS
        assert_eq!(aspath.attr_value[4], 253); // MSB of second AS
        assert_eq!(aspath.attr_value[5], 233); // LSB of second AS
        assert_eq!(aspath.attr_value[6], 2); // AS_SEQUENCE Segment type
        assert_eq!(aspath.attr_value[7], 2); // num ASes in AS_SEQUENCE
        assert_eq!(aspath.attr_value[8], 0); // MSB of first AS
        assert_eq!(aspath.attr_value[9], 131); // LSB of first AS
        assert_eq!(aspath.attr_value[10], 118); // MSB of second AS
        assert_eq!(aspath.attr_value[11], 229); // LSB of second AS
    }

    #[test]
    fn build_next_hop_v4() {
        let ip = IpAddr::V4(Ipv4Addr::from_str("192.168.0.0").unwrap());
        let n_hop = PathAttrBuilder::<NextHop>::new().next_hop(ip).build();

        // Path Attr checks
        assert_eq!(n_hop.attr_flags, 64u8);
        assert_eq!(n_hop.attr_type_code, 3u8);
        assert_eq!(n_hop.attr_len, PathAttrLen::Std(4));
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(n_hop.attr_value.as_slice());
        assert_eq!(Ipv4Addr::from(bytes), Ipv4Addr::from_str("192.168.0.0").unwrap());
    }

    #[test]
    fn build_next_hop_v6() {
        // Using Ipv6 Neighbor Solicitation dest address (multicast) because why not?
        let ip = IpAddr::V6(Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0x0001, 0xFFCC, 0xCCCC));
        let n_hop = PathAttrBuilder::<NextHop>::new().next_hop(ip).build();

        // Path n_hop.attr checks
        assert_eq!(n_hop.attr_flags, 64u8);
        assert_eq!(n_hop.attr_type_code, 3u8);
        assert_eq!(n_hop.attr_len, PathAttrLen::Std(16));

        // Cumbersome to build an Ipv6Addr, so will just compare the octets.
        if let IpAddr::V6(inner) = ip {
            assert_eq!(n_hop.attr_value, inner.octets());
        } else {
            panic!()
        }
    }

    #[test]
    fn build_med() {
        let med = PathAttrBuilder::<Med>::new().metric(1000u32).build();

        // Path Attr checks
        assert_eq!(med.attr_flags, 128);
        assert_eq!(med.attr_type_code, 4);
        assert_eq!(med.attr_len, PathAttrLen::Std(4));
        // Value check. Should be 1000 decomposed as a u8
        assert_eq!(med.attr_value, vec![0u8, 0, 3, 232]);
    }

    #[test]
    fn build_local_pref() {
        let lp = PathAttrBuilder::<LocalPref>::new().local_pref(1000).build();

        // Path Attr checks
        assert_eq!(lp.attr_flags, 64);
        assert_eq!(lp.attr_type_code, 5);
        assert_eq!(lp.attr_len, PathAttrLen::Std(4));
        // Value check. Should be 1000 decomposed as a u8
        assert_eq!(lp.attr_value, vec![0u8, 0, 3, 232]);
    }

    #[test]
    fn build_atomic_agg() {
        let aa = PathAttrBuilder::<AtomicAggregate>::new().build();

        // Path Attr checks
        assert_eq!(aa.attr_flags, 64);
        assert_eq!(aa.attr_type_code, 6);
        assert_eq!(aa.attr_len, PathAttrLen::Std(0));
        assert_eq!(aa.attr_value.is_empty(), true);
        assert_eq!(aa.attr_value.len(), 0);
    }

    #[test]
    fn build_aggregator_v4() {
        let ag = PathAttrBuilder::<Aggregator>::new()
            .aggregator(65000, Ipv4Addr::new(1, 1, 1, 1))
            .build();

        // Path Attr checks
        assert_eq!(ag.attr_flags, 192);
        assert_eq!(ag.attr_type_code, 7);
        assert_eq!(ag.attr_len, PathAttrLen::Std(6));
        
        // First get the appropriate bytes from the vec as u8 arrays
        let mut last_as_bytes: [u8; 2] = [0u8; 2];
        let mut ip_bytes: [u8; 4] = [0u8; 4];
        last_as_bytes.copy_from_slice(ag.attr_value[0..=1].as_ref());
        ip_bytes.copy_from_slice(ag.attr_value[2..=5].as_ref());

        // Now can check to see if they are correct.
        assert_eq!(u16::from_be_bytes(last_as_bytes), 65000u16);
        assert_eq!(Ipv4Addr::from(ip_bytes), Ipv4Addr::new(1, 1, 1, 1));
    }
}