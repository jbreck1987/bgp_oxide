// This module contains all the BGP Control Message serialization and transfer logic.
// Since this is an RFC based protocol, the serialization will be home-rolled for accuracy as opposed
// to using Serde.


// GLOBAL TO-DOs:
// 1. Make sure that all arbitrary "puts" into the BytesMut types are Big Endian!
// 2. Add tests for OpenSerializer
use std::{
    net::{IpAddr}
};
use crate::{message_types::{
    ByteLen, Header, MessageType, Notification, Open, Route, Tlv, Update
}, path_attrs::{PathAttr, PathAttrLen}};

use crate::errors::{
    NotifErrorCode,
    OpenMsgErrSubcode,
    MsgHeaderErrSubcode,
    UpdateMsgErrSubcode,
};

use bytes::{BytesMut, BufMut};
// Each Control Message will have a custom Serializer type which will be combined into a MessageBuilder
struct HeaderSerializer {
    msg: Header,
    buf: BytesMut,
}

impl HeaderSerializer {
    pub fn new(msg: Header) -> Self {
        Self {
            msg,
            buf: BytesMut::with_capacity(19),
        }
    }
    pub fn serialize(mut self) -> BytesMut {
        self.buf.put(self.msg.marker());
        self.buf.put_u16(self.msg.length());
        self.buf.put_u8(self.msg.message_type());
        self.buf
    }
}

struct NotificationSerializer {
    msg: Notification,
    buf: BytesMut,
}

impl NotificationSerializer {
    pub fn new(msg: Notification) -> Self {
        let len = msg.data().len();
        Self {
            msg,
            buf: BytesMut::with_capacity(2 + len),
        }
    }
    // TO-DO: Consider borrowing here in case we need to keep a copy of this
    // serializer (and, its internal Notification msg) for whatever reaosn
    pub fn serialize(mut self) -> BytesMut {
        self.buf.put_u8(self.msg.err_code());
        self.buf.put_u8(self.msg.err_subcode());
        self.buf.put(self.msg.data());
        self.buf
    }
}
struct OpenSerializer {
    msg: Open,
    buf: BytesMut,
}

impl OpenSerializer {
    pub fn new(msg: Open) -> Self {
        let params_len = msg.opt_params_len();
        Self {
            msg,
            buf: BytesMut::with_capacity(10 + params_len as usize)
        }
    }
    pub fn serialize(mut self) -> BytesMut {
        self.buf.put_u8(self.msg.version());
        self.buf.put_u16(self.msg.my_as());
        self.buf.put_u16(self.msg.hold_time());
        self.buf.put_u32(self.msg.bgp_id());
        self.buf.put_u8(self.msg.opt_params_len());

        // Check to make sure there are any optional parameter Tlvs
        // to serialize
        match self.msg.opt_params_len() {
            0 => self.buf,
            _ => {
                for tlv in self.msg.opt_params() {
                    self.buf.put_u8(tlv.param_type());
                    self.buf.put_u8(tlv.param_length());
                    self.buf.put(tlv.param_value());
                }
                self.buf
            }
        }
    }
}

struct RouteSerializer {
    msg: Route,
    buf: BytesMut
}

impl RouteSerializer {
    pub fn new(msg: Route) -> Self {
        let byte_len = msg.byte_len();
        Self {
            msg,
            buf: BytesMut::with_capacity(byte_len)
        }
    }
    pub fn serialize(mut self) -> BytesMut {
        self.buf.put_u8(self.msg.length());
        match self.msg.prefix() {
            IpAddr::V4(x) => self.buf.put(x.octets().as_slice()),
            IpAddr::V6(x) => self.buf.put(x.octets().as_slice()),
        }
        self.buf
    }
}

struct PathAttrSerializer {
    msg: PathAttr,
    buf: BytesMut
}

impl PathAttrSerializer {
    pub fn new(msg: PathAttr) -> Self {
        let byte_len = msg.byte_len();
        Self {
            msg,
            buf: BytesMut::with_capacity(byte_len)
        }
    }
    pub fn serialize(mut self) -> BytesMut {
        self.buf.put_u8(self.msg.attr_flags());
        self.buf.put_u8(self.msg.attr_type_code());
        // Serialize based on standard or extended length size
        match self.msg.attr_len() {
            &PathAttrLen::Std(x) => self.buf.put_u8(x),
            &PathAttrLen::Ext(x) => self.buf.put_u16(x),
        }
        self.buf.put(self.msg.attr_value());
        self.buf
    }
}
struct UpdateSerializer {
    msg: Update,
    buf: BytesMut,
}

impl UpdateSerializer {
    pub fn new(msg: Update) -> Self {
        let w_routes_len = msg.withdrawn_routes_len();
        let pa_len = msg.total_path_attr_len();
        Self {
            msg,
            // This will not capture the entire Update message length, but will lower number of resizes
            buf: BytesMut::with_capacity(2 + w_routes_len as usize + 2 + pa_len as usize)
        }
    }
    pub fn serialize(mut self) -> BytesMut {
        self.buf.put_u16(self.msg.withdrawn_routes_len());

        // Check to see if there any withdrawn routes to serialize
        // and serialize if so
        match self.msg.withdrawn_routes_mut() {
            Some(serial_vec) => {
                for route in serial_vec {
                    // Create RouteSerializer and serialize the route
                    let rs = RouteSerializer::new(route);
                    self.buf.put(rs.serialize())
                }
            },
            None => ()
        }

        self.buf.put_u16(self.msg.total_path_attr_len());
        
        // Check to see if there are any PAs to serialize
        // and serialize if so.
        match self.msg.path_attrs_mut() {
            Some(vec) => {
                for path_attr in vec.to_owned() {
                    // Create RouteSerializer and serialize the route.
                    let ps = PathAttrSerializer::new(path_attr);
                    self.buf.put(ps.serialize())
                }
            },
            None => ()
        }
        // Finally, check to see if any NLRI need to be serialized
        match self.msg.nlri_mut() {
            Some(serial_vec) => {
                for route in serial_vec {
                    // Create RouteSerializer and serialize the route
                    let rs = RouteSerializer::new(route);
                    self.buf.put(rs.serialize())
                }
            },
            None => ()
        }
        self.buf

    }
}

#[cfg(test)]
mod tests {
    use crate::message_types::OpenBuilder;

    use super::*;

    #[test]
    fn test_serialize_header() {
        let msg = Header::new(1, MessageType::Open);
        let serializer = HeaderSerializer::new(msg);
        let correct = vec![1u8,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1];
        let serialized: Vec<_> = serializer.serialize().into();
        assert_eq!(correct, serialized);
    }
    #[test]
    fn test_serialize_notification() {
        let code = NotifErrorCode::OpenMessageError(OpenMsgErrSubcode::BadPeerAs);
        let msg = Notification::new(code, 1);
        let serializer = NotificationSerializer::new(msg);
        let correct = vec![2u8, 2, 0, 0, 0, 0, 0, 0, 0, 1];
        let serialized: Vec<_> = serializer.serialize().into();
        assert_eq!(correct, serialized);
    }
    #[test]
    fn test_serialize_open_no_params() {
        let msg = OpenBuilder::new(4, 65000, 180, 1).build();
        let serializer = OpenSerializer::new(msg);

        // Build the correct byte array
        let mut correct: Vec<u8> = Vec::new();
        correct.push(4u8);
        correct.extend_from_slice(65000u16.to_be_bytes().as_slice());
        correct.extend_from_slice(180u16.to_be_bytes().as_slice());
        correct.extend_from_slice(1u32.to_be_bytes().as_slice());
        correct.push(0u8);

        let serialized: Vec<_> = serializer.serialize().into();
        assert_eq!(correct, serialized);
    }
    #[test]
    fn test_serialize_open_with_params() {
        let param1 = Tlv::new(1, vec![1, 1, 1, 1, 1, 1]);
        let param2 = Tlv::new(1, vec![1]);
        let msg = OpenBuilder::new(4, 65000, 180, 1)
            .opt_param(param1)
            .opt_param(param2)
            .build();
        let serializer = OpenSerializer::new(msg);
        // Build the correct byte array
        let mut correct: Vec<u8> = Vec::new();
        correct.push(4u8);
        correct.extend_from_slice(65000u16.to_be_bytes().as_slice());
        correct.extend_from_slice(180u16.to_be_bytes().as_slice());
        correct.extend_from_slice(1u32.to_be_bytes().as_slice());
        correct.push(11u8);
        correct.push(1u8);
        correct.push(6u8);
        correct.extend_from_slice(vec![1u8,1,1,1,1,1].as_slice());
        correct.push(1u8);
        correct.push(1u8);
        correct.push(1u8);
    }
}