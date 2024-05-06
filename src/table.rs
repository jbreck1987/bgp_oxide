// Holds logic for the BGP RIBs and Decision Process

use std::{
    cmp, collections::{HashMap, HashSet}, hash::{Hash, Hasher}, net::
    {IpAddr, Ipv4Addr, Ipv6Addr}
};

use crate::path_attrs::{
    PathAttr,
    ORIGIN,
    LOCAL_PREF,
    MED,
    AS_PATH,
    AGGREGATOR,
    ATOMIC_AGGREGATE,
    NEXT_HOP,
};

pub (crate) enum RouteSource {
    Ebgp,
    Ibgp
}

// Used to hold information related to running the decision process for a particular path
// The best way to store paths would be using
// a BTreeSet, ordered based on some preference function, based on the given decision process terms.
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
    pub fn path_attrs(&self) -> &Vec<PathAttr> {
        &self.path_attrs
    }
}
// This data structure is used to simplify comparisons between many candidate paths
// to a destination as opposed to destructuring the raw path attribute data for each comparison.

#[derive(Eq, PartialEq)]
pub(crate) struct DecisionProcessData {
    local_pref: Option<u32>,
    as_path_len: u8,
    origin: u8,
    med: u32,
    route_souce: u8,
    igp_cost: u64,
    peer_id: u32,
    // Deciding to use IpAddr here since cmp is already defined
    peer_addr: IpAddr
}

// Implementing PartialOrd (and Ord, implicitly) for this data structure will be critical in
// allowing the best paths to easily be found and for feasible paths to always
// be ordered (using min heaps per destination).
impl PartialOrd for DecisionProcessData {
    fn partial_cmp(&self, other: &Self) ->Option<std::cmp::Ordering> {
        // First check to see if LOCAL_PREF can be compared
       let lp_ord = match (self.local_pref, other.local_pref) {
            (Some(left), Some(right)) => {
                // If so, compare local_pref and return Option
                // with the result.
                Some(left.cmp(&right))
            },
            (None, _) | (_, None) => { None }
        };
        // Define a closure that does the non local pref comparisons
        let f = || {
            self.as_path_len.cmp(&other.as_path_len)
            .then_with(|| self.origin.cmp(&other.origin))
            .then_with(|| self.med.cmp(&other.med))
            .then_with(|| self.route_souce.cmp(&other.route_souce))
            .then_with(|| self.igp_cost.cmp(&other.igp_cost))
            .then_with(|| self.peer_id.cmp(&other.peer_id))
            .then_with(|| self.peer_addr.cmp(&other.peer_addr))
        };
        // Now can check the result and continue the comparison if necessary
        match lp_ord {
            Some(ord) => {
                // Return the comp value if LP was deciding factor, otherwise continue
                // the comparisons through the closure
                if ord != std::cmp::Ordering::Equal {
                    return Some(ord);
                }
                Some(f())
            }
            None => { Some(f()) }
        }
    }
}

impl Ord for DecisionProcessData {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
    
}

// This is an entry in the Path Attribute Table. The goal is to have a data structure that contains
// the raw Path Attribute data (for Update creation) while also containing a representation of the relevant
// parameters necessary for running the Decision process. This implies some data duplication, but since some PAs
// aren't relevant for the Decision Process (and one structue can be pointed to by many routes), this seems
// reasonable.
pub(crate) struct PathAttributeTableEntry {
    entry: Vec<(DecisionProcessData, Vec<PathAttr>)>
}

pub(crate) struct PathAttributeTable {
    table: HashSet<PathAttributeTableEntry>
}

pub(crate) struct BgpTableEntry<'a> {
    route_attrs: Vec<RouteAttribute>,
    changed: bool,
    best: Option<&'a RouteAttribute>
}
impl BgpTableEntry<'_> {
    pub fn new() -> Self {
        Self { route_attrs: Vec::new(), changed: false, best: None }
    }
    // Runs the decision process given a new path
    // and appends the path to the existing list
    pub fn decision(&mut self, new_path: RouteAttribute) {
        // Add new path to the table entry
        self.route_attrs.push(new_path);
        for path in self.route_attrs.iter() {
            // Check whether route is internal or external
            match path.route_source() {
                RouteSource::Ibgp => {
                    todo!()
                },
                RouteSource::Ebgp => {
                    todo!()
                }
            }
        }
    }
    fn compare_local_pref(&mut self, candidate_path: &RouteAttribute) -> Option<&RouteAttribute> {
        // First define closure to extract the LOCAL_PREF value from each path. This function
        // assumes the LOCAL_PREF PA exists in all paths of the table entry.
        let f = |r: &RouteAttribute| {
            let lp: Option<&PathAttr> = r.path_attrs()
            .iter()
            .filter(|pa| {
                pa.attr_type_code() == LOCAL_PREF
            })
            .last();
            
            // Return the LOCAL_PREF value after casting to u32
            if let Some(pa) = lp {
                let mut buf: [u8; 4] = [0u8; 4];
                buf.copy_from_slice(pa.attr_value());
                u32::from_be_bytes(buf)
            } else { // This branch implies that None was returned from the iter adaptor and there is an issue
                0
            }
        };

        // Now we can map over all the paths to find the one with maximum LP and compare it to the new candidate path
        // First need to add the new candidate path to the table.
        todo!()
        
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

// Will be generic over AFI (v4/v6)
struct BgpTable<'a, A> {
    table: HashMap<A, BgpTableEntry<'a>>
}