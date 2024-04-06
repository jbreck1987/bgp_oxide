use std::{cell::RefCell}; // For testing private structs

// Definitions for the basic message types in BGP.
static OPEN_VALUE: u8 = 1;
static UPDATE_VALUE: u8 = 2;
static KEEP_VALUE: u8 = 3;
static NOT_VALUE: u8 = 4;

type KeepAlive = Header;
trait PAttr {}

#[derive(Debug)]
pub struct Header {
     marker: [u8; 16],
    // Limited to 16 bits
     length: usize,
    // Type; limited to 8 bits
     message_type: u8,
}

impl Header {
    pub fn new(length: usize, message_type: MessageType) -> Self {
        // First need to actually get the bit values from the MessageType
        let mtype = match message_type {
            MessageType::Open => OPEN_VALUE,
            MessageType::Update => UPDATE_VALUE,
            MessageType::KeepAlive => KEEP_VALUE,
            MessageType::Notification => NOT_VALUE
        };
        Self {
            marker: [1; 16],
            length,
            message_type: mtype
        }
    }
}

pub enum MessageType {
    Open,
    Update,
    KeepAlive,
    Notification
}
struct Open {
    version: u8,
    // "My Autonomous System"
    my_as: u16,
    holdtime: u16,
    // "BGP Identifier"
    bgp_id: u32,
    // "Optional Parameters Length"; total length of the optional parameters
    // section IN NUMBER OF OCTETS (BYTES)
    opt_params_len: u8,
    // "Optional Parameters". This is a variable length container containing objects that
    // are inhomogenous in length.
    opt_params: Vec<Tlv>,
}
struct Update {
    withdrawn_routes_len: u16,
    withdrawn_routes: Vec<Route>,
    total_path_attr_len: u16,
    // Using trait object since can have a mixture of normal and extended Path Attributes here.
    path_attrs: Vec<Box::<dyn PAttr>>,
    // Only difference from withdrawn routes is that the PAs apply to the NLRI, while the withdrawn
    // routes only need prefix info to be removed.
    nlri: Vec<Route>,
}
struct Notification {
    // "Error Code"
    err_code: u8,
    // "Error Subcode"
    err_subcode: u8,
    // "Data"; variable length. There is no length field for this since
    // the length can be dynamically determined since each structure in the
    // message has a known length.
    data: Vec<u8>
}
struct Tlv { // These will be constructed on the fly
    param_type: u8,
    param_length: u8,
    param_value: Vec<u8>,
}
impl Tlv {
    pub fn new(param_type: u8, param_value: Vec<u8>) -> Self {
        Self {
            param_type,
            param_length: param_value.len() as u8, // Only need length of parameter value (in octets)
            param_value,
        }
    }
}

struct Route {
    // Could potentially use the crate for IpAddressing, but wouuld need this to stay
    // general such that routes for non-IP address families can be supported. Need to check to the
    // spec to see how NLRI are handled. TBD...
    length: usize,
    prefix: Vec<u8>,
}

impl Route {
    fn new(length: usize, prefix: Vec<u8>) -> Self {
        Self {
            length,
            prefix,
        }
    }
}
 struct PathAttr {
    attr_flags: u8,
    attr_type_code: u8,
    attr_len: u8,
    attr_value: Vec<u8>,
    
 }
 impl PAttr for PathAttr {}

  struct PathAttrExt {
    // Extended path attributes give 16 bits to determine the length of the attribute value (in octets)
    attr_flags: u8,
    attr_type_code: u8,
    attr_len: u16,
    attr_value: Vec<u8>,
 }
 impl PAttr for PathAttrExt {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_header_open() {
        let header = Header::new(100, MessageType::Open);
        let cell = RefCell::new(header);
        assert_eq!(cell.borrow().length, 100);
        assert_eq!(cell.borrow().marker, [1u8; 16]);
        assert_eq!(cell.borrow().message_type, 1u8);
    }
    #[test]
    fn build_header_update() {
        let header = Header::new(100, MessageType::Update);
        let cell = RefCell::new(header);
        assert_eq!(cell.borrow().length, 100);
        assert_eq!(cell.borrow().marker, [1u8; 16]);
        assert_eq!(cell.borrow().message_type, 2u8);
    }
    #[test]
    fn build_header_keep() {
        let header = Header::new(100, MessageType::KeepAlive);
        let cell = RefCell::new(header);
        assert_eq!(cell.borrow().length, 100);
        assert_eq!(cell.borrow().marker, [1u8; 16]);
        assert_eq!(cell.borrow().message_type, 3u8);
    }
    #[test]
    fn build_header_not() {
        let header = Header::new(100, MessageType::Notification);
        let cell = RefCell::new(header);
        assert_eq!(cell.borrow().length, 100);
        assert_eq!(cell.borrow().marker, [1u8; 16]);
        assert_eq!(cell.borrow().message_type, 4u8);
    }
    #[test]
    fn build_tlv() {
        let tlv = Tlv::new(2, vec![9, 8]);
        let cell = RefCell::new(tlv);
        assert_eq!(cell.borrow().param_length, 2);
        assert_eq!(cell.borrow().param_type, 2);
    }
}