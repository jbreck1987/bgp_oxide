// This module will contain all the error types that can be used in the NOTIFICATION message.
// Seems like the easiest way to define these is using enums.
use std::convert::From;


// Constants
// ** Notification Error Codes **
const MSG_HEADER_ERR: u8 = 1;
const OPEN_MSG_ERR: u8 = 2;
const UPDATE_MSG_ERR: u8 = 3;
const HOLD_TIMER_EXP_ERR: u8 = 4;
const FSM_ERR: u8 = 5;
const CEASE_ERR: u8 = 6;

// ** Update Message Error Subcodes **

// Malformed Attribute List
const MALFORMED_ATTR_LIST: u8 = 1;
 // Unrecognized Well-Known Attribute
const UNRECOGNIZED_WK_ATTR: u8 = 2;
// Missing Well-Known Attribute
const MISSING_WK_ATTR: u8 = 3;
// Attribute Flags Error
const ATTR_FLAGS_ERROR: u8 = 4;
// Attribute Length Error
const ATTR_LENGTH_ERROR: u8 = 5;
// Invalid Origin Attribute
const INVALID_ORIGIN_ATTR: u8 = 6;
// Invalid Next Hop Attribute
const INVALID_NEXT_HOP_ATTR: u8 = 8;
// Optional Attribute Error
const OPTIONAL_ATTR_ERROR: u8 = 9;
// Invalid Network Field
const INVALID_NETWORK_FIELD: u8 = 10;
// Malformed AS_PATH
const MALFORMED_AS_PATH: u8 = 11;

// ** Open Message Subcodes **

// Unsupported Version Number.
const UNSUPPORTED_VER_NUM: u8 = 1;
// Bad Peer AS.
const BAD_PEER_AS: u8 = 2;
// Bad BGP Identifier.
const BAD_BGP_ID: u8 = 3;
// Unsupported Optional Parameter.
const UNSUPPORTED_OPT_PARAM: u8 = 4;
// Unacceptable Hold Time.
const UNACCEPTABLE_HOLD_TIME: u8 = 6;

// ** Message Header Error Subcodes **

// Connection Not Synchronized.
const CONN_NOT_SYNCED: u8 = 1;
// Bad Message Length.
const BAD_MSG_LEN: u8 = 2;
// Bad Message Type.
const BAD_MSG_TYPE: u8 = 3;

#[derive(Debug, PartialEq)]
pub(crate) enum NotifErrorCode {
    MessageHeaderError(MsgHeaderErrSubcode),
    OpenMessageError(OpenMsgErrSubcode),
    UpdateMessageError(UpdateMsgErrSubcode),
    HoldTimerExpired,
    FiniteStateMachineError,
    Cease
}

impl NotifErrorCode {
    pub fn as_ref(&self) -> &Self {
        &self
    }
}


#[derive(Debug, PartialEq)]
pub(crate) enum OpenMsgErrSubcode {
    UnsupportedVerNum,
    BadPeerAs,
    BadBgpId,
    UnsupportedOptParam,
    UnacceptableHoldTime,
}

impl OpenMsgErrSubcode {
    pub fn as_ref(&self) -> &Self {
        &self
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum MsgHeaderErrSubcode {
    ConnNotSynced,
    BadMsgLen,
    BadMsgType,
}

impl MsgHeaderErrSubcode {
    pub fn as_ref(&self) -> &Self {
        &self
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum UpdateMsgErrSubcode {
    MalformedAttrList,
    UnrecognizedWkAttr,
    MissingWkAttr,
    AttrFlagsError,
    AttrLengthError,
    InvalidOriginAttr,
    InvalidNextHopAttr,
    OptionalAttrError,
    InvalidNetworkField,
    MalformedAsPath,
}

impl UpdateMsgErrSubcode {
    pub fn as_ref(&self) -> &Self {
        &self
    }
}

// Using From here as opposed to using generating functions
// for a simpler API when serializing.
impl From<&NotifErrorCode> for u8 {
    fn from(value: &NotifErrorCode) -> Self {
        match value {
            NotifErrorCode::MessageHeaderError(_) => MSG_HEADER_ERR,
            NotifErrorCode::OpenMessageError(_) => OPEN_MSG_ERR,
            NotifErrorCode::UpdateMessageError(_) => UPDATE_MSG_ERR,
            NotifErrorCode::HoldTimerExpired => HOLD_TIMER_EXP_ERR,
            NotifErrorCode::FiniteStateMachineError => FSM_ERR,
            NotifErrorCode::Cease => CEASE_ERR,
        }
    }
}

impl From<&OpenMsgErrSubcode> for u8 {
    fn from(value: &OpenMsgErrSubcode) -> Self {
        match value {
            OpenMsgErrSubcode::UnsupportedVerNum => UNSUPPORTED_VER_NUM,
            OpenMsgErrSubcode::BadPeerAs => BAD_PEER_AS,
            OpenMsgErrSubcode::BadBgpId => BAD_BGP_ID,
            OpenMsgErrSubcode::UnsupportedOptParam => UNSUPPORTED_OPT_PARAM,
            OpenMsgErrSubcode::UnacceptableHoldTime => UNACCEPTABLE_HOLD_TIME
        }
    }
}

impl From<&MsgHeaderErrSubcode> for u8 {
    fn from(value: &MsgHeaderErrSubcode) -> Self {
        match value {
            MsgHeaderErrSubcode::ConnNotSynced => CONN_NOT_SYNCED,
            MsgHeaderErrSubcode::BadMsgLen => BAD_MSG_LEN,
            MsgHeaderErrSubcode::BadMsgType => BAD_MSG_TYPE,
        }
    }
}

impl From<&UpdateMsgErrSubcode> for u8 {
    fn from(value: &UpdateMsgErrSubcode) -> Self {
        match value {
            UpdateMsgErrSubcode::MalformedAttrList => MALFORMED_ATTR_LIST,
            UpdateMsgErrSubcode::UnrecognizedWkAttr => UNRECOGNIZED_WK_ATTR,
            UpdateMsgErrSubcode::MissingWkAttr => MISSING_WK_ATTR,
            UpdateMsgErrSubcode::AttrFlagsError => ATTR_FLAGS_ERROR,
            UpdateMsgErrSubcode::AttrLengthError => ATTR_LENGTH_ERROR,
            UpdateMsgErrSubcode::InvalidOriginAttr => INVALID_ORIGIN_ATTR,
            UpdateMsgErrSubcode::InvalidNextHopAttr => INVALID_NEXT_HOP_ATTR,
            UpdateMsgErrSubcode::OptionalAttrError => OPTIONAL_ATTR_ERROR,
            UpdateMsgErrSubcode::InvalidNetworkField => INVALID_NETWORK_FIELD,
            UpdateMsgErrSubcode::MalformedAsPath => MALFORMED_AS_PATH,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_hold_timer_exp() {
        let val = 4u8;
        let err = NotifErrorCode::HoldTimerExpired.as_ref();
        let converted: u8 = err.into();
        assert_eq!(val, converted);
    }
    #[test]
    fn convert_fsm_err() {
        let val = 5u8;
        let err = NotifErrorCode::FiniteStateMachineError.as_ref();
        let converted: u8 = err.into();
        assert_eq!(val, converted);
    }
    #[test]
    fn convert_cease() {
        let val = 6u8;
        let err = NotifErrorCode::Cease.as_ref();
        let converted: u8 = err.into();
        assert_eq!(val, converted);
    }
    #[test]
    fn convert_msg_header_err_and_conn_not_synced() {
        let code = 1u8;
        let subcode = 1u8;
        let err = &NotifErrorCode::MessageHeaderError(MsgHeaderErrSubcode::ConnNotSynced);
        if let NotifErrorCode::MessageHeaderError(inner_subcode) = err {
            let inner_converted: u8 = inner_subcode.into();
            let outer_converted: u8 = err.into();
            assert_eq!(inner_converted, subcode);
            assert_eq!(outer_converted, code);
        }
    }
}