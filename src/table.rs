// Holds logic for the BGP RIBs and Decision Process

use std::{collections::HashMap,
    net::IpAddr};
use crate::path_attrs::{
    PathAttr,
};

enum RouteSource {
    Ebgp,
    Ibgp
}

// Used to hold information related to running the decision process for a particular path
pub(crate) struct RouteAttribute {
    peer_id: IpAddr, 
    peer_address: IpAddr, 
    route_source: RouteSource, 
    path_attrs: Vec<PathAttr>,
    best_path: bool,
    igp_metric: u64,
}
impl RouteAttribute {
    pub fn new(peer_id: IpAddr,
               peer_address: IpAddr,
               route_source: RouteSource,
               path_attrs: Vec<PathAttr>) -> Self {
        Self {
            peer_id,
            peer_address,
            route_source,
            path_attrs,
            best_path: false,
            igp_metric: 0
        }
    }
    pub fn route_source(&self) -> &RouteSource {
        &self.route_source
    }
    fn compare_local_pref(&self, other:&RouteAttribute) -> Option<&RouteAttribute> {
        todo!();
    }
    fn compare_as_path(&self, other:&RouteAttribute) -> Option<&RouteAttribute> {
        todo!();
    }
    fn compare_origin(&self, other:&RouteAttribute) -> Option<&RouteAttribute> {
        todo!();
    }
    fn compare_med(&self, other:&RouteAttribute) -> Option<&RouteAttribute> {
        todo!();
    }
    fn compare_route_source(&self, other:&RouteAttribute) -> Option<&RouteAttribute> {
        todo!();
    }
    fn compare_igp_metric(&self, other:&RouteAttribute) -> Option<&RouteAttribute> {
        todo!();
    }
    fn compare_peer_id(&self, other:&RouteAttribute) -> Option<&RouteAttribute> {
        todo!();
    }
    fn compare_peer_addr(&self, other:&RouteAttribute) -> Option<&RouteAttribute> {
        todo!();
    }
}

pub(crate) struct TableEntry {
    route_attrs: Vec<RouteAttribute>,
    changed: bool
}
impl TableEntry {
    pub fn new() -> Self {
        Self { route_attrs: Vec::new(), changed: false }
    }
    // Runs the decision process given a new path
    // and appends the path to the existing list
    pub fn decision(&mut self, new_path: &RouteAttribute) {
        for path in self.route_attrs.iter() {
            // Check whether route is internal or external
            match path.route_source() {
                RouteSource::Ibgp => {
                    // Chain together potential calls that implement the decision process.
                    // This seems reasonable since at the first None, no real computation will be
                    // done and the None is just propagated.
                    let _ = path.compare_local_pref(new_path)
                    .and_then(|x| path.compare_as_path(x))
                    .and_then(|x| path.compare_origin(x))
                    .and_then(|x| path.compare_med(x))
                    .and_then(|x| path.compare_route_source(x))
                    .and_then(|x| path.compare_igp_metric(x))
                    .and_then(|x| path.compare_peer_id(x))
                    .and_then(|x| path.compare_peer_addr(x));
                },
                RouteSource::Ebgp => {
                    let _ = path.compare_as_path(new_path)
                    .and_then(|x| path.compare_origin(x))
                    .and_then(|x| path.compare_med(x))
                    .and_then(|x| path.compare_route_source(x))
                    .and_then(|x| path.compare_igp_metric(x))
                    .and_then(|x| path.compare_peer_id(x))
                    .and_then(|x| path.compare_peer_addr(x));
                }
            }
        }
    }


}
struct BgpTable<A> {
    table: HashMap<A, TableEntry>
}