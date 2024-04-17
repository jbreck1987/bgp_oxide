// Module for defining the data structures used in the BGP FSM
// Each connection has session parameters that are used to keep the
// state of the connection (E.g. which the BGP FSM is in an associated timers)
// (See RFC4271; Pg. 37)

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
// This struct currently only supports the mandatory session attributes 
// given in RFC 4271, Pg. 37
pub(crate) struct Session {
    state: State,
    connect_retry_ctr: usize,
    connect_retry_timer: usize,
    connect_retry_time: usize,
    hold_timer: usize,
    hold_time: usize,
    keepalive_timer: usize,
    keepalive_time: usize,
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