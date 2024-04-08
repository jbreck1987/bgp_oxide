// This module will contain all the error types that can be used in the NOTIFICATION message.
// Seems like the easiest way to define these is using enums.
use std::error::Error;
use std::fmt::Display;


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
    MessageHeaderError(u8),
    OpenMessageError(u8),
    UpdateMessageError(u8),
    HoldTimerExpired(u8),
    FiniteStateMachineError(u8),
    Cease(u8),
}


impl NotifErrorCode {
    // To get the default variants, will use these generating functions.
    pub(crate) fn msg_header_err(subcode: u8) -> Self {
        Self::MessageHeaderError(1)
    }
    pub(crate) fn open_msg_err(subcode: u8) -> Self {
        Self::OpenMessageError(2)
    }
    pub(crate) fn update_msg_err() -> Self {
         Self::UpdateMessageError(3)       
    }
    pub(crate) fn hold_timer_exp() -> Self {
        Self::HoldTimerExpired(4)
    }
    pub(crate) fn fsm_err() -> Self {
        Self::FiniteStateMachineError(5)
    }
    pub(crate) fn cease() -> Self {
        Self::Cease(6)
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum NotifErrorSubCode {
    MessageHeaderError(u8),
    OpenMessageError(u8),
    UpdateMessageError(u8),
}
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
        let err = NotifErrorCode::hold_timer_exp();
        assert_eq!(err, NotifErrorCode::HoldTimerExpired(4));
    }
    #[test]
    fn build_default_fsm_err() {
        let err = NotifErrorCode::fsm_err();
        assert_eq!(err, NotifErrorCode::FiniteStateMachineError(5));
    }
    #[test]
    fn build_default_cease() {
        let err = NotifErrorCode::cease();
        assert_eq!(err, NotifErrorCode::Cease(6));
    }

}