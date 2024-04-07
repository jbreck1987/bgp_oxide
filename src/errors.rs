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
    MessageHeaderError(u8, NotifErrorSubCode),
    OpenMessageError(u8, NotifErrorSubCode),
    UpdateMessageError(u8, NotifErrorSubCode),
    HoldTimerExpired(u8),
    FiniteStateMachineError(u8),
    Cease(u8),
}
#[derive(Debug, PartialEq)]
pub(crate) enum NotifErrorSubCode {
    MessageHeaderError(u8),
    OpenMessageError(u8),
    UpdateMessageError(u8),
}

impl NotifErrorCode {
    // To get the default variants, will use these generating functions.
    pub(crate) fn msg_header_err(subcode: u8) -> Result<Self, SubcodeError> {
        match subcode {
            1 | 2 | 3 => {
                Ok(Self::MessageHeaderError(1, NotifErrorSubCode::MessageHeaderError(subcode)))
            }
            _ => {
                Err(SubcodeError(String::from("Valid values are 1, 2, or 3.")))
            }
        }
    }
    pub(crate) fn open_msg_err(subcode: u8) -> Result<Self, SubcodeError> {
        match subcode {
            1..=6 => {
                Ok(Self::OpenMessageError(2, NotifErrorSubCode::OpenMessageError(subcode)))
            }
            _ => {
                Err(SubcodeError(String::from("Valid values are integers 1 through 6.")))
            }
        }
    }
    pub(crate) fn update_msg_err(subcode: u8) -> Result<Self, SubcodeError> {
        match subcode {
            1..=11 => {
                Ok(Self::UpdateMessageError(3, NotifErrorSubCode::UpdateMessageError(subcode)))
            }
            _ => {
                Err(SubcodeError(String::from("Valid values are integers 1 through 11.")))
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_default_msg_header_err_valid_subcode() {
        for i in 1u8..3 {
            if let Ok(err) = NotifErrorCode::msg_header_err(i) {
                assert_eq!(err, NotifErrorCode::MessageHeaderError(1, NotifErrorSubCode::MessageHeaderError(i)));
            } else {
                panic!("Expected values 1 through 3 to result in an Ok(), got Err()!")
            }
        }
    }
    #[test]
    fn build_default_msg_header_err_invalid_subcode() {
        let err = NotifErrorCode::msg_header_err(5);
        match err {
            Err(e) => {
              assert_eq!(e, SubcodeError(String::from("Valid values are 1, 2, or 3.")))
            }
            _ => {
                panic!("Expected Err(), got Ok()!");
            }
        }
    }
    #[test]
    fn build_default_open_msg_err_valid_subcode() {
        for i in 1u8..6 {
            if let Ok(err) = NotifErrorCode::open_msg_err(i) {
                assert_eq!(err, NotifErrorCode::OpenMessageError(2, NotifErrorSubCode::OpenMessageError(i)));
            } else {
                panic!("Expected values 1 through 6 to result in an Ok(), got Err()!")
            }
        }
    }
    #[test]
    fn build_default_open_msg_err_invalid_subcode() {
        let err = NotifErrorCode::open_msg_err(7);
        match err {
            Err(e) => {
              assert_eq!(e, SubcodeError(String::from("Valid values are integers 1 through 6.")))
            }
            _ => {
                panic!("Expected Err(), got Ok()!");
            }
        }
    }
    #[test]
    fn build_default_update_msg_err_valid_subcode() {
        for i in 1u8..=11 {
            if let Ok(err) = NotifErrorCode::update_msg_err(i) {
                assert_eq!(err, NotifErrorCode::UpdateMessageError(3, NotifErrorSubCode::UpdateMessageError(i)));
            } else {
                panic!("Expected values 1 through 11 to result in an Ok(), got Err()!")
            }
        }
    }
    #[test]
    fn build_default_update_msg_err_invalid_subcode() {
        let err = NotifErrorCode::update_msg_err(12);
        match err {
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