// This module will contain all the error types that can be used in the NOTIFICATION message.
// Seems like the easiest way to define these is using enums.
use std::error::Error;
use std::fmt::Display;
use std::convert::From;


// Constants
// ** Notification Error Codes **
const MSG_HEADER_ERR_VAL: u8 = 1;
const OPEN_MSG_ERR_VAL: u8 = 2;
const UPDATE_MSG_ERR_VAL: u8 = 3;
const HOLD_TIMER_EXP_ERR_VAL: u8 = 4;
const FSM_ERR_VAL: u8 = 5;
const CEASE_ERR_VAL: u8 = 6;

// ** Notification Error Subcodes **
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

// Need to define an error for incorrect Message Subcode values
#[derive(Debug, PartialEq)]
struct SubcodeError(String);
impl Display for SubcodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let SubcodeError(msg) = self;
        write!(f, "{}", msg)
    }
}

impl Error for SubcodeError {}


#[derive(Debug, PartialEq)]
pub(crate) enum NotifErrorCode {
    MessageHeaderError,
    OpenMessageError,
    UpdateMessageError,
    HoldTimerExpired,
    FiniteStateMachineError,
    Cease
}

// Using From here as opposed to using generating functions
// for a simpler API.
impl From<NotifErrorCode> for u8 {
    fn from(value: NotifErrorCode) -> Self {
        match value {
            NotifErrorCode::MessageHeaderError => MSG_HEADER_ERR_VAL,
            NotifErrorCode::OpenMessageError => OPEN_MSG_ERR_VAL,
            NotifErrorCode::UpdateMessageError => UPDATE_MSG_ERR_VAL,
            NotifErrorCode::HoldTimerExpired => HOLD_TIMER_EXP_ERR_VAL,
            NotifErrorCode::FiniteStateMachineError => FSM_ERR_VAL,
            NotifErrorCode::Cease => CEASE_ERR_VAL,
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum NotifErrorSubCode {
    MessageHeaderError(u8),
    OpenMessageError(u8),
    UpdateMessageError(u8),
}
// Using generating functions here (for now) due to the one to many relationship between subcode type and
// value. Eventually, this could be replaced with a similar API as above, but it's a lot of work. Eventually,
// could probably use the builder pattern here to couple subcodes and codes.
impl NotifErrorSubCode {
    pub(crate) fn msg_header_err(subcode: u8) -> Result<Self, SubcodeError> {
        match subcode {
            1 | 2 | 3 => {
                Ok(Self::MessageHeaderError(subcode))
            }
            _ => {
                Err(SubcodeError(String::from("Valid values are 1, 2, or 3.")))
            }
        }
    }
    pub(crate) fn open_msg_err(subcode: u8) -> Result<Self, SubcodeError> {
        match subcode {
            1..=6 => {
                Ok(Self::OpenMessageError(subcode))
            }
            _ => {
                Err(SubcodeError(String::from("Valid values are integers 1 through 6.")))
            }
        }
    }
    pub(crate) fn update_msg_err(subcode: u8) -> Result<Self, SubcodeError> {
        match subcode {
            1..=11 => {
                Ok(Self::UpdateMessageError(subcode))
            }
            _ => {
                Err(SubcodeError(String::from("Valid values are integers 1 through 11.")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_default_valid_subcode_msg_header_err() {
        for i in 1u8..=3 {
            match NotifErrorSubCode::msg_header_err(i) {
                Ok(err) => {
                    assert_eq!(err, NotifErrorSubCode::MessageHeaderError(i));
                }
                _ => {
                    panic!("Expected values 1 through 3 to result in an Ok(), got Err()!")
                }
            }
        }
    }
    #[test]
    fn build_default_invalid_subcode_msg_header_err() {
        match NotifErrorSubCode::msg_header_err(5) {
            Err(e) => {
              assert_eq!(e, SubcodeError(String::from("Valid values are 1, 2, or 3.")))
            }
            _ => {
                panic!("Expected Err(), got Ok()!");
            }
        }
    }
    #[test]
    fn build_default_valid_subcode_open_msg_err() {
        for i in 1u8..=6 {
            match NotifErrorSubCode::open_msg_err(i) {
                Ok(err) => {
                    assert_eq!(err, NotifErrorSubCode::OpenMessageError(i));
                }
                _ => {
                    panic!("Expected values 1 through 6 to result in an Ok(), got Err()!")
                }
            }
        }
    }
    #[test]
    fn build_default_invalid_subcode_open_msg_err() {
        match NotifErrorSubCode::open_msg_err(7) {
            Err(e) => {
              assert_eq!(e, SubcodeError(String::from("Valid values are integers 1 through 6.")))
            }
            _ => {
                panic!("Expected Err(), got Ok()!");
            }
        }
    }
    #[test]
    fn build_default_valid_subcode_update_msg_err() {
        for i in 1u8..=11 {
            match NotifErrorSubCode::update_msg_err(i) {
                Ok(err) => {
                    assert_eq!(err, NotifErrorSubCode::UpdateMessageError(i));
                }
                _ => {
                    panic!("Expected values 1 through 11 to result in an Ok(), got Err()!")
                }
            }
        }
    }
    #[test]
    fn build_default_invalid_subcode_update_msg_err() {
        match NotifErrorSubCode::update_msg_err(12) {
            Err(e) => {
              assert_eq!(e, SubcodeError(String::from("Valid values are integers 1 through 11.")))
            }
            _ => {
                panic!("Expected Err(), got Ok()!");
            }
        }
    }
    #[test]
    fn build_default_hold_timer_exp() {
        let val = 4u8;
        let err = NotifErrorCode::HoldTimerExpired;
        let converted: u8 = err.into();
        assert_eq!(val, converted);
    }
    #[test]
    fn build_default_fsm_err() {
        let val = 5u8;
        let err = NotifErrorCode::FiniteStateMachineError;
        let converted: u8 = err.into();
        assert_eq!(val, converted);
    }
    #[test]
    fn build_default_cease() {
        let val = 6u8;
        let err = NotifErrorCode::Cease;
        let converted: u8 = err.into();
        assert_eq!(val, converted);
    }

}