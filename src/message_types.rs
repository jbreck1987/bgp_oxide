use std::{
    cell::RefCell,
    convert::From,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};
use bytes::Buf;

use crate::{
    errors::{
        MsgHeaderErrSubcode,
        NotifErrorCode,
        OpenMsgErrSubcode,
        UpdateMsgErrSubcode
    },
    path_attrs::{
        PathAttr,
        PathAttrBuilder,
        Med}
};

use serde::{Serialize, Deserialize};
use bgp4_serde::to_bytes;

// Definitions for the basic message types in BGP.
static OPEN_VALUE: u8 = 1;
static UPDATE_VALUE: u8 = 2;
static KEEP_VALUE: u8 = 3;
static NOT_VALUE: u8 = 4;

type KeepAlive = Header;

#[derive(Debug, Serialize)]
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

impl Open {
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn my_as(&self) -> u16 {
        self.my_as
    }
    pub fn hold_time(&self) -> u16 {
        self.holdtime
    }
    pub fn bgp_id(&self) -> u32 {
        self.bgp_id
    }
    pub fn opt_params_slice(&self) -> &[Tlv] {
        self.opt_params.as_slice()
    }
    pub fn opt_params(self) -> Vec<Tlv> {
        self.opt_params
    }
    pub fn opt_params_len(&self) -> u8 {
        self.opt_params_len
    }

}

pub(crate) struct OpenBuilder {
    version: u8,
    my_as: u16,
    holdtime: u16,
    bgp_id: u32,
    opt_params_len: u8,
    opt_params: Vec<Tlv>,

}

impl OpenBuilder {
    pub fn new(bgp_ver: u8, my_as: u16, holdtime: u16, bgp_id: u32) -> Self {
        Self {
            version: bgp_ver,
            my_as,
            holdtime,
            bgp_id,
            opt_params_len: 0,
            opt_params: Vec::new(),
        }
    }
    pub fn opt_param(mut self, tlv: Tlv) -> Self {
        self.opt_params.push(tlv);
        self
    }
    pub fn build(mut self) -> Open {
        let opt_len = match self.opt_params.len() {
            0 => 0, // If no optional params added, length is 0
            _ => { // otherwise, sum the lengths (in octets) for each TLV in the list
                self.opt_params
                .iter()
                .map(|tlv| 2 + tlv.param_length) // constant 2 for param len and type fields
                .sum()
            }
        };

        Open {
            version: self.version,
            my_as: self.my_as,
            holdtime: self.holdtime,
            bgp_id: self.bgp_id,
            opt_params_len: opt_len,
            opt_params: self.opt_params,
        }
    }
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
pub(crate) struct Tlv { // These will be constructed on the fly
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

    pub fn param_type(&self) -> u8 {
        self.param_type
    }
    pub fn param_length(&self) -> u8 {
        self.param_length
    }
    pub fn param_value(&self) -> &[u8] {
        self.param_value.as_slice()

    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Route {
    // RFC 4271 explicitly states that the prefixes are IP addresses.
    // Will use the std::net package for this
    length: u8,
    prefix: IpAddr,
}

impl Route {
    pub fn new(length: u8, prefix: IpAddr) -> Self {
        Self {
            length,
            prefix,
        }
    }
    pub fn prefix_len(&self) -> u8 {
        self.length
    }
    pub fn prefix_v4(&self) -> Option<Ipv4Addr> {
        match self.prefix {
            IpAddr::V4(addr) => Some(addr),
            _ => None
        }
    }
    pub fn prefix_v6(&self) -> Option<Ipv6Addr> {
        match self.prefix {
            IpAddr::V6(addr) => Some(addr),
            _ => None
            
        }
    }
    pub fn len(&self) -> usize {
        // Size of the route in octets
        match self.prefix {
            IpAddr::V4(_) => 1 + 4,
            IpAddr::V6(_) => 1 + 16,
        }
    }
} 

// Struct to couple Routes with PAs. Will be used in the Builder for Update messages.
pub(crate) struct Nlri {
    routes: Vec<Route>,
    path_attrs: Vec<PathAttr>
}
impl Nlri {
    pub fn new(routes: &[Route], pas: &[PathAttr]) -> Self {
        let mut this_routes: Vec<Route> = Vec::new();
        this_routes.extend_from_slice(routes);

        let mut this_pas: Vec<PathAttr> = Vec::new();
        this_pas.extend_from_slice(pas);
        Self {
            routes: this_routes,
            path_attrs: this_pas
        }
    }
}


pub (crate) struct Update {
    // Length in octets
    withdrawn_routes_len: u16,
    withdrawn_routes: Option<Vec<Route>>,
    // Length in octets
    total_path_attr_len: u16,
    path_attrs: Option<Vec<PathAttr>>,
    // Only difference from withdrawn routes is that the PAs apply to the NLRI, while the withdrawn
    // routes only need prefix info to be removed.
    nlri: Option<Vec<Route>>,
}

impl Update {
    pub fn withdrawn_routes_len(&self) -> u16 {
        self.withdrawn_routes_len
    }
    pub fn withdrawn_routes(&self) -> Option<&[Route]> {
        match &self.withdrawn_routes {
            Some(x) => Some(x.as_slice()),
            None => None
        }
    }
    pub fn withdrawn_routes_mut(&mut self) -> Option<&mut Vec<Route>> {
        self.withdrawn_routes.as_mut()
    }
    pub fn total_path_attr_len(&self) -> u16 {
        self.total_path_attr_len
    }
    pub fn path_attrs(&self) -> Option<&[PathAttr]> {
        // This function is ugly, so much indirection.
        // TO-DO: Try to rework with less indirection.
        match &self.path_attrs {
            Some(x) => Some(x.as_slice()),
            None => None
        }
    }
    pub fn path_attrs_mut(&mut self) -> Option<&mut Vec<PathAttr>> {
        self.path_attrs.as_mut()
    }
    pub fn nlri(&self) -> Option<&[Route]> {
        match self.nlri.as_ref() {
            Some(x) => Some(x.as_slice()),
            None => None
        }
    }
    pub fn nlri_mut(&mut self) -> Option<&mut Vec<Route>> {
        self.nlri.as_mut()

    }
}

pub(crate) struct UpdateBuilder {
    withdrawn_routes_len: u16,
    withdrawn_routes: Option<Vec<Route>>,
    total_path_attr_len: u16,
    path_attrs: Option<Vec<PathAttr>>,
    nlri: Option<Vec<Route>>,
}

impl UpdateBuilder {
    pub fn new() -> Self {
        Self {
            withdrawn_routes_len: 0,
            withdrawn_routes: None,
            total_path_attr_len: 0,
            path_attrs: None,
            nlri: None,
        }
    }
    pub fn withdrawn_routes(mut self, routes: Vec<Route>) -> Self {
        match routes.len() {
            // If len of routes is 0, erroneous use of the method, just
            // return self using default value.
            0 => self,
            _ => {
                // Only ever expect either Ipv4 or Ipv6 routes, per RFC4271.
                self.withdrawn_routes_len = {
                    routes.iter().map(|r| r.len()).sum::<usize>() as u16
                };
                self.withdrawn_routes = Some(routes);
                self
            }
        }
    }
    pub fn nlri(mut self, nlri: Nlri) -> Self {
        // Again, if either data member is empty,
        // this is erroneous. Will return a default update.
        match (nlri.routes.is_empty(), nlri.path_attrs.is_empty()) {
            (false, false) => {
                self.total_path_attr_len = {
                    nlri.path_attrs.iter().map(|pa| pa.attr_len_octets()).sum::<usize>() as u16
                };
                self.path_attrs = Some(nlri.path_attrs);
                self.nlri = Some(nlri.routes);
                self
            },
            _ => self
        }
    }
    pub fn build(self) -> Update {
        Update {
            withdrawn_routes_len: self.withdrawn_routes_len,
            withdrawn_routes: self.withdrawn_routes,
            total_path_attr_len: self.total_path_attr_len,
            path_attrs: self.path_attrs,
            nlri: self.nlri
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::path_attrs::{self, PaBuilder};

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
    fn serialize_header_open() {
        let header = Header::new(100, MessageType::Open);
        let buf = to_bytes(header).unwrap();
        // Check total length first; 19 bytes
        assert_eq!(buf.len(), 19);

        // Check marker
        let extracted_marker = buf.get(0..16).unwrap();
        assert_eq!(&[1u8; 16], extracted_marker);
    
        // Check Length
        let extracted_length = buf.get(16..18).unwrap();
        assert_eq!(100u16.to_be_bytes(), extracted_length);

        // Check Message type
        let extracted_msg_type = buf.get(18).unwrap();
        assert_eq!(OPEN_VALUE, *extracted_msg_type);

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
    fn new_tlv() {
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

    #[test]
    fn build_open_no_opt_param() {
        let msg = OpenBuilder::new(4, 65000, 180, 1).build();
        assert_eq!(msg.version, 4);
        assert_eq!(msg.my_as, 65000);
        assert_eq!(msg.holdtime, 180);
        assert_eq!(msg.bgp_id, 1);
        assert!(msg.opt_params.is_empty());
        assert_eq!(msg.opt_params_len, 0);
    }
    
    #[test]
    fn build_open_with_opt_params() {
        let param1 = Tlv::new(1, vec![1, 1, 1, 1, 1, 1]);
        let param2 = Tlv::new(1, vec![1]);
        let msg = OpenBuilder::new(4, 65000, 180, 1)
            .opt_param(param1)
            .opt_param(param2)
            .build();

        assert_eq!(msg.version, 4);
        assert_eq!(msg.my_as, 65000);
        assert_eq!(msg.holdtime, 180);
        assert_eq!(msg.bgp_id, 1);
        assert_eq!(msg.opt_params.len(), 2);
        assert_eq!(msg.opt_params_len, 11);
    }

    #[test]
    fn build_update_withdrawn_only() {
        // build the withdrawn routes vec
        let route = Route::new(
            24, 
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        let mut routes: Vec<Route> = Vec::new();
        routes.push(route);

        // no PAs, can build the Update msg
        let update = UpdateBuilder::new().withdrawn_routes(routes).build();

        // Checking values
        assert_eq!(update.withdrawn_routes_len(), 1 + 4);
        match update.path_attrs() {
            Some(_) => panic!("Expected no PAs!"),
            None => ()
        }
        assert_eq!(update.total_path_attr_len(), 0);
        match update.nlri() {
            Some(_) => panic!("Expected no NLRI!"),
            None => ()
        }
    }
    #[test]
    fn build_update_nlri_only() {
        // build the nlri routes vec
        let route = Route::new(
            24, 
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        let mut routes: Vec<Route> = Vec::new();
        routes.push(route);

        // build the pa vec
        let pa = PathAttrBuilder::<Med>::new().metric(1000).build();
        let pas = vec![pa];
        let pa_len = pas.iter().map(|pa| pa.attr_len_octets()).sum::<usize>() as u16;

        // build the nlri
        let nlri = Nlri::new(routes.as_slice(), pas.as_slice());

        // build the Update msg
        let update = UpdateBuilder::new().nlri(nlri).build();

        // Checking values
        assert_eq!(update.withdrawn_routes_len(), 0);
        match update.path_attrs() {
            Some(_) => (),
            None => panic!("Expected to see PAs!")
        }
        assert_eq!(update.total_path_attr_len(), pa_len);
        match update.nlri() {
            Some(_) => (),
            None => panic!("Expected to see NLRI!")
        }
    }

    #[test]
    fn build_update_nlri_and_withdrawn() {
        // build the withdrawn routes vec
        let w_route = Route::new(
            24, 
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        let mut w_routes: Vec<Route> = Vec::new();
        w_routes.push(w_route);

        // build the nlri routes vec
        let n_route = Route::new(
            24, 
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        let mut n_routes: Vec<Route> = Vec::new();
        n_routes.push(n_route);

        // build the pa vec
        let pa = PathAttrBuilder::<Med>::new().metric(1000).build();
        let pas = vec![pa];
        let pa_len = pas.iter().map(|pa| pa.attr_len_octets()).sum::<usize>() as u16;

        // build the nlri
        let nlri = Nlri::new(n_routes.as_slice(), pas.as_slice());

        // build the Update msg
        let update = UpdateBuilder::new().withdrawn_routes(w_routes).nlri(nlri).build();

        // Checking values
        assert_eq!(update.withdrawn_routes_len(), 1 + 4);
        match update.withdrawn_routes() {
            Some(_) => (),
            None => panic!("Expected to see Withdrawn routes!")
        }
        match update.path_attrs() {
            Some(_) => (),
            None => panic!("Expected to see PAs!")
        }
        assert_eq!(update.total_path_attr_len(), pa_len);
        match update.nlri() {
            Some(_) => (),
            None => panic!("Expected to see NLRI!")
        }
    }
}