// Definitions for inter-service messaging types

// This structure contains information for the BGP table to run the decision process
// and install paths. This message is queued up after decoding a valid Update message.
use crate::{
    message_types::Route,
    path_attrs::{self, OriginValue, PathAttr},
    table::RouteSource,
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
        self.origin.clone().into()
    }
    pub fn med(&self) -> u32 {
        self.med
    }
    pub fn route_source(&self) -> RouteSource {
        self.route_source.clone()
    }
    pub fn igp_cost(&self) -> u64 {
        self.igp_cost
    }
    pub fn path_attrs(&self) -> Vec<PathAttr>{
        self.path_attrs.clone()
    }
    pub fn routes(&self) -> Vec<Route> {
        self.routes.clone()
    }
}

// Used for creating RR messages for testing
pub (crate) struct MockReceivedRoutesBuilder {
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
 impl MockReceivedRoutesBuilder {
    pub fn new(routes: Vec<Route>, pa: Vec<PathAttr>) -> Self {
        Self {
                peer_id: Ipv4Addr::new(192, 168, 1, 1),
                peer_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                last_as: 65000,
                local_pref: Some(100),
                as_path_len: 5,
                origin: OriginValue::Igp,
                med: 1000,
                route_source: RouteSource::Ebgp,
                igp_cost: 1000,
                path_attrs: pa,
                routes
        }
    }
    pub fn peer_id(mut self, peer_id: Ipv4Addr) -> Self {
        self.peer_id = peer_id;
        self
    }
    pub fn peer_addr(mut self, peer_addr: IpAddr) -> Self {
        self.peer_addr = peer_addr;
        self
    }
    pub fn last_as(mut self, last_as: u16) -> Self {
        self.last_as = last_as;
        self
    }
    pub fn local_pref(mut self, lp: u32) -> Self {
        self.local_pref = Some(lp);
        self
    }
    pub fn as_path_len(mut self, path_len: u8) -> Self {
        self.as_path_len = path_len;
        self
    }
    pub fn origin(mut self, origin: OriginValue) -> Self {
        self.origin = origin;
        self
    }
    pub fn med(mut self, med: u32) -> Self {
        self.med = med;
        self
    }
    pub fn route_source(mut self, rs: RouteSource) -> Self {
        self.route_source = rs;
        self
    }
    pub fn igp_cost(mut self, cost: u64) -> Self {
        self.igp_cost = cost;
        self
    }
    pub fn build(self) -> ReceivedRoutes {
        ReceivedRoutes::new(
            self.peer_id,
            self.peer_addr,
            self.last_as,
            self.local_pref,
            self.as_path_len,
            self.origin,
            self.med,
            self.route_source,
            self.igp_cost,
            self.path_attrs,
            self.routes)
    }
 }