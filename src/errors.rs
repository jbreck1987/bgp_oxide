// This module will contain all the error types that can be used in the NOTIFICATION message.
// Seems like the easiest way to define these is using an enum.

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
    pub(crate) fn msg_header_err() -> Self {
        Self::MessageHeaderError(1)
    }
    pub(crate) fn open_msg_err() -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_default_msg_header_err() {
        let err = NotifErrorCode::msg_header_err();
        assert_eq!(err, NotifErrorCode::MessageHeaderError(1));
    }
    #[test]
    fn build_default_open_msg_err() {
        let err = NotifErrorCode::open_msg_err();
        assert_eq!(err, NotifErrorCode::OpenMessageError(2));
    }
    #[test]
    fn build_default_update_msg_err() {
        let err = NotifErrorCode::update_msg_err();
        assert_eq!(err, NotifErrorCode::UpdateMessageError(3));
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