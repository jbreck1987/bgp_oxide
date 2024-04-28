// This module contains all the BGP Control Message serialization and transfer logic.
// Since this is an RFC based protocol, the serialization will be home-rolled for accuracy as opposed
// to using Serde.


// GLOBAL TO-DOs:
// 1. Make sure that all arbitrary "puts" into the BytesMut types are Big Endian!
// The "put_<bit_size>" methods already enforce this.
// 2. Add tests for OpenSerializer

use crate::message_types::{
    Header,
    Open,
    Notification,
    Update,
    MessageType,
};

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


#[cfg(test)]
mod tests {
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
        todo!()
    }
    #[test]
    fn test_serialize_open_with_params() {
        todo!()
    }
}