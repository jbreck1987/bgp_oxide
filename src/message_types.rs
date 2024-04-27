use std::{
    cell::RefCell,
    convert::From,
};
use crate::errors::{
    NotifErrorCode,
    OpenMsgErrSubcode,
    UpdateMsgErrSubcode,
    MsgHeaderErrSubcode,
};
use crate::path_attrs;

// Definitions for the basic message types in BGP.
static OPEN_VALUE: u8 = 1;
static UPDATE_VALUE: u8 = 2;
static KEEP_VALUE: u8 = 3;
static NOT_VALUE: u8 = 4;

type KeepAlive = Header;

#[derive(Debug)]
pub struct Header {
     marker: [u8; 16],
    // Limited to 16 bits
     length: u16,
    // Type; limited to 8 bits
     message_type: u8,
}

impl Header {
    pub fn new(length: u16, message_type: MessageType) -> Self {
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
    pub fn marker(&self) -> &[u8] {
        self.marker.as_slice()
    }
    pub fn length(&self) -> u16 {
        self.length
    }
    pub fn message_type(&self) -> u8 {
        self.message_type
    }
}
pub enum MessageType {
    Open,
    Update,
    KeepAlive,
    Notification
}
pub (crate) struct Open {
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
pub (crate) struct Update {
    withdrawn_routes_len: u16,
    withdrawn_routes: Vec<Route>,
    total_path_attr_len: u16,
    // Using trait object since can have a mixture of normal and extended Path Attributes here.
    path_attrs: Vec<Box::<dyn path_attrs::PAttr>>,
    // Only difference from withdrawn routes is that the PAs apply to the NLRI, while the withdrawn
    // routes only need prefix info to be removed.
    nlri: Vec<Route>,
}
pub(crate) struct Notification {
    // Notification Error Code
    err_code: u8,
    // Error Subcode
    err_subcode: u8, 
    // Data; variable length. There is no length field for this since
    // the length can be dynamically determined since each structure in the
    // message has a known length.
    data: Vec<u8>
}

impl Notification {
    pub fn new(error: NotifErrorCode, data: usize) -> Self {
        // Extract the error code and subcode from the NotifErrorCode instance
        let err_code: u8 = error.as_ref().into();
        let err_subcode: u8 = match error.as_ref() {
            NotifErrorCode::MessageHeaderError(inner) => inner.into(),
            NotifErrorCode::OpenMessageError(inner) => inner.into(),
            NotifErrorCode::UpdateMessageError(inner) => inner.into(),
            // RFC 4271, Pg.21; Error codes without defined subcodes should use 0 as subcode
            _ => 0
        };
        Self {
            err_code,
            err_subcode,
            data: Vec::from(data.to_be_bytes())
        }
    }
    pub fn err_code(&self) -> u8 {
        self.err_code
    }
    pub fn err_subcode(&self) -> u8 {
        self.err_subcode
    }
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
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
    #[test]
    fn build_notification_with_subcode() {
        let err_code = NotifErrorCode::OpenMessageError(OpenMsgErrSubcode::BadBgpId);
        let msg = Notification::new(err_code, 1);
        assert_eq!(msg.err_code(), 2);
        assert_eq!(msg.err_subcode(), 3);

        let mut data: [u8; 8] = [0; 8];
        data.copy_from_slice(msg.data());
        assert_eq!(usize::from_be_bytes(data), 1);
    }
    #[test]
    fn build_notification_no_subcode() {
        let err_code = NotifErrorCode::Cease;
        let msg = Notification::new(err_code, 1);
        assert_eq!(msg.err_code(), 6);
        assert_eq!(msg.err_subcode(), 0);

        let mut data: [u8; 8] = [0; 8];
        data.copy_from_slice(msg.data());
        assert_eq!(usize::from_be_bytes(data), 1);
    }
}