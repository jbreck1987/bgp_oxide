// Definitions for inter-service messaging types

// This structure contains information for the BGP table to run the decision process
// and install paths. This message is queued up after decoding a valid Update message.
use crate::{
    message_types::Route, path_attrs::{OriginValue, PathAttr}, table::RouteSource
};
use std::net::{
    Ipv4Addr,
    IpAddr
};


pub struct ReceivedRoutes {
    peer_id: Ipv4Addr,
    peer_addr: IpAddr,
    last_as: u16,
    local_pref: Option<u32>,
    as_path_len: u8,
    origin: OriginValue,
    med: u32,
    route_source: RouteSource,
    igp_cost: u64,
    path_attrs: Vec<PathAttr>,
    routes: Vec<Route>
}
impl ReceivedRoutes {
    pub fn new(peer_id: Ipv4Addr,
               peer_addr: IpAddr,
               last_as: u16,
               local_pref: Option<u32>,
               as_path_len: u8,
               origin: OriginValue,
               med: u32,
               route_source: RouteSource,
               igp_cost: u64,
               path_attrs: Vec<PathAttr>,
               routes: Vec<Route> ) -> Self {
        Self {
            peer_id,
            peer_addr,
            last_as,
            local_pref,
            as_path_len,
            origin,
            med,
            route_source,
            igp_cost,
            path_attrs,
            routes
        }
    }
}
