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
// Associated Functions
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
// Methods
impl ReceivedRoutes {
    pub fn peer_id(&self) -> Ipv4Addr{
        self.peer_id
    }
    pub fn peer_addr(&self) -> IpAddr {
        self.peer_addr
    }
    pub fn last_as(&self) -> u16 {
        self.last_as
    }
    pub fn local_pref(&self) -> Option<u32> {
        self.local_pref
    }
    pub fn as_path_len(&self) -> u8 {
       self.as_path_len 
    }
    pub fn origin(&self) -> u8 {
        self.origin.into()
    }
    pub fn med(&self) -> u32 {
        self.med
    }
    pub fn route_source(&self) -> RouteSource {
        self.route_source
    }
    pub fn igp_cost(&self) -> u64 {
        self.igp_cost
    }
    pub fn path_attrs(&self) -> Vec<PathAttr>{
        self.path_attrs
    }
    pub fn routes(&self) -> Vec<Route> {
        self.routes
    }
}
