// Module for defining the data structures used in the BGP FSM
// Each connection has session parameters that are used to keep the
// state of the connection (E.g. which the BGP FSM is in an associated timers)
// (See RFC4271; Pg. 37)

use std::net::IpAddr;

const DEFAULT_HOLD_TIME: usize = 90;
const DEFAULT_KEEPALIVE_TIME: usize = 30;
const DEFAULT_CONNECT_RETRY_TIME: usize = 120;

// Marker trait for FsmEvents such that we can be generic
pub(crate) trait FsmEvent {}

// Seems like an enum is a good representatin of the State for a peer. Assuming this will need to be behind 
// some sort of lock in the multi-threaded case.
pub(crate) enum State{
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established
}
// Contains all the values that are necessary to configure a BGP peer
// that a user will configure.
pub struct BgpPeer {
    pub peer_address: IpAddr,
    pub remote_as: u16,
    session: PeerSession,
}
// This struct currently only supports the mandatory session attributes 
// given in RFC 4271, Pg. 37
// Contains all the values related to the BGP FSM for a given peer
pub(crate) struct PeerSession {
    state: State,
    connect_retry_ctr: usize,
    connect_retry_timer: usize,
    connect_retry_time: usize,
    hold_timer: usize,
    hold_time: usize,
    keepalive_timer: usize,
    keepalive_time: usize,
}

impl PeerSession {
    pub(crate) fn reset_connect_retry_ctr(&mut self) {
        // Self-explanatory. Resets the connection
        // retry counter to 0.
        self.connect_retry_ctr = 0;
    }
    pub(crate) fn reset_connect_retry_timer(&mut self) {
        // Resets connection retry timer to 0.
        self.connect_retry_timer = 0;
    }
    pub(crate) fn reset_hold_timer(&mut self) {
        self.hold_timer = 0;
    }
    pub(crate) fn reset_keep_timer(&mut self) {
        self.keepalive_timer = 0;
    }
}

pub struct PeerSessionBuilder {
    state: State,
    connect_retry_ctr: usize,
    connect_retry_timer: usize,
    connect_retry_time: usize,
    hold_timer: usize,
    hold_time: usize,
    keepalive_timer: usize,
    keepalive_time: usize,
}

// See RFC 4721, Pg. 90 for suggested default timer thresholds.
impl PeerSessionBuilder {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            connect_retry_ctr: 0,
            connect_retry_timer: 0,
            connect_retry_time: DEFAULT_CONNECT_RETRY_TIME,
            hold_timer: 0,
            hold_time: DEFAULT_HOLD_TIME,
            keepalive_timer: 0,
            keepalive_time: DEFAULT_KEEPALIVE_TIME,
        }
    }
    pub fn conn_retry_time(mut self, time: usize) -> Self {
        // Build value for ConnecRetryTime
        self.connect_retry_time = time;
        self
    }
    pub fn hold_time(mut self, time: usize) -> Self {
        // Build value for HoldTime
        self.hold_time = time;
        self
    }
    pub fn keep_time(mut self, time: usize) -> Self {
        // Build value for KeepaliveTime
        self.keepalive_time = time;
        self
    }
    pub fn build(mut self) -> PeerSession {
        PeerSession {
            state: self.state,
            connect_retry_ctr: self.connect_retry_ctr,
            connect_retry_timer: self.connect_retry_timer,
            connect_retry_time: self.connect_retry_time,
            hold_timer: self.hold_timer,
            hold_time: self.hold_time,
            keepalive_timer: self.keepalive_timer,
            keepalive_time: self.keepalive_time,
        }
    }
}

// Now we'll define the mandatory FSM input events given in RFC 4271, Pg. 43
struct ManualStart;
struct ManualStop;
struct ConnectRetryTimerExpires;
struct HoldTimerExpires;
struct KeepaliveTimerExpires;
struct TcpCrAcked;
struct TcpConnectionConfirmed;
struct TcpConnectionFails;
struct BGPOpen;
struct BGPHeaderErr;
struct BGPOpenMsgErr;
struct NotifMsgVerErr;
struct NotifMsg;
struct KeepAliveMsg;
struct UpdateMsg;
struct UpdateMsgErr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_peer_default() {
        let peer_session = PeerSessionBuilder::new().build();
        assert_eq!(peer_session.connect_retry_time, DEFAULT_CONNECT_RETRY_TIME);
        assert_eq!(peer_session.hold_time, DEFAULT_HOLD_TIME);
        assert_eq!(peer_session.keepalive_time, DEFAULT_KEEPALIVE_TIME);
    }
    #[test]
    fn build_peer_chg_keep() {
        let peer_session = PeerSessionBuilder::new().keep_time(10).build();
        assert_eq!(peer_session.connect_retry_time, 120);
        assert_eq!(peer_session.hold_time, 90);
        assert_eq!(peer_session.keepalive_time, 10);
    }
    #[test]
    fn build_peer_chg_hold() {
        let peer_session = PeerSessionBuilder::new().hold_time(10).build();
        assert_eq!(peer_session.connect_retry_time, 120);
        assert_eq!(peer_session.hold_time, 10);
        assert_eq!(peer_session.keepalive_time, 30);
    }
    #[test]
    fn build_peer_chg_conn() {
        let peer_session = PeerSessionBuilder::new().conn_retry_time(10).build();
        assert_eq!(peer_session.connect_retry_time, 10);
        assert_eq!(peer_session.hold_time, 90);
        assert_eq!(peer_session.keepalive_time, 30);
    }
    #[test]
    fn build_peer_chg_all() {
        let peer_session = PeerSessionBuilder::new()
            .conn_retry_time(20)
            .hold_time(180)
            .keep_time(90)
            .build();
        assert_eq!(peer_session.connect_retry_time, 20);
        assert_eq!(peer_session.hold_time, 180);
        assert_eq!(peer_session.keepalive_time, 90);
    }


}