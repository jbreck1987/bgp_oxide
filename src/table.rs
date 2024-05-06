// Holds logic for the BGP RIBs and Decision Process

use std::{
    cmp,
    cmp::Reverse,
    collections::{HashMap, HashSet, BinaryHeap},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    rc::Rc,
};

use crate::{message_types::{Nlri, Update}, path_attrs::{
    PathAttr, AGGREGATOR, AS_PATH, ATOMIC_AGGREGATE, LOCAL_PREF, MED, NEXT_HOP, ORIGIN
}};

#[derive(Eq, PartialEq, Hash, Clone)]
pub (crate) enum RouteSource {
    Ebgp,
    Ibgp
}

impl From<&RouteSource> for u8 {
    fn from(value: &RouteSource) -> Self {
        match value {
            RouteSource::Ebgp => 0,
            RouteSource::Ibgp => 1
        }
    }
}

// This data structure is used to simplify comparisons between many candidate paths
// to a destination as opposed to destructuring the raw path attribute data for each comparison.
#[derive(Eq, PartialEq, Hash)]
pub(crate) struct DecisionProcessData {
    local_pref: Option<u32>,
    as_path_len: u8,
    last_as: u16,
    origin: u8,
    med: u32,
    route_souce: RouteSource,
    igp_cost: u64,
    peer_id: Ipv4Addr,
    peer_addr: IpAddr
}

impl DecisionProcessData {
    // Not sure on the API here, set as todo
    pub fn new() -> Self { todo!() }
}

// Implementing PartialOrd (and Ord, implicitly) for this data structure will be critical in
// allowing the best paths to easily be found and for feasible paths to always
// be ordered (using min heaps per destination). This effectively implements the Decision Process.
// Paths that evaluate to "less than" are better paths.
impl PartialOrd for DecisionProcessData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // First check to see if local pref can be compared
       let lp_ord = match (self.local_pref, other.local_pref) {
            // If so, compare local pref and return Option
            // with the result. Note that the order for cmp() is switched!
            // We want to prefer higher local preference, but make that evaluate
            // to "less than".
            (Some(left), Some(right)) => { Some(right.cmp(&left)) },
            (None, _) | (_, None) => { None }
        };
        // Define a closure that does the non local pref comparisons
        let f = || {
            let comp = self.as_path_len.cmp(&other.as_path_len) // Shortest AS path wins
            .then(self.origin.cmp(&other.origin)); // Lowest origin wins

            // Before comparing med, need to verify both paths have same last_as.
            // lowest med wins.
            let comp = if self.last_as == other.last_as {
                comp.then(self.med.cmp(&other.med))
            } else {
                comp
            };
            // Continue comparions
            let this_rs: u8 = (&self.route_souce).into();
            let other_rs: u8 = (&other.route_souce).into();
            comp.then(this_rs.cmp(&other_rs)) // lowest route source wins (based on From impl)
            .then(self.igp_cost.cmp(&other.igp_cost)) // Lowest IGP cost wins
            .then(self.peer_id.cmp(&other.peer_id)) // Lowest peer id wins
            .then(self.peer_addr.cmp(&other.peer_addr)) // Lowest peer addr wins
        };

        // Now can check the lp ordering Option and continue the comparison if necessary
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
// parameters necessary for running the Decision Process. This implies some data duplication, but since some PAs
// aren't relevant for the Decision Process (and one table entry can be pointed to by many routes), this seems
// reasonable.
#[derive(PartialEq, Eq, Hash)]
pub(crate) struct PathAttributeTableEntry {
    decision_data: DecisionProcessData, 
    raw_path_attrs: Vec<PathAttr>
}

impl PathAttributeTableEntry {
    pub fn new(decision_data: DecisionProcessData, mut raw_pas: Vec<PathAttr>) -> Self {
        // For hashing purposes, we want the Path Attributes to be sorted. Choosing to sort
        // by Path Attribute Type Code.
        raw_pas.sort_by_cached_key(|pa| pa.attr_type_code());
        Self {
            decision_data,
            raw_path_attrs: raw_pas
        }
    }
}

impl PartialOrd for PathAttributeTableEntry {
    // Ordering for the full data structure is unnecessary, will reuse the implementation
    // for DecisionProcessData
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.decision_data.partial_cmp(&other.decision_data)
    }
}

impl Ord for PathAttributeTableEntry {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

// Want the Entry to be behind an Rc so that when no paths are pointing to it,
// it can be cleaned out of the table.
pub(crate) struct PathAttributeTable {
    table: HashSet<Rc<PathAttributeTableEntry>>
}

// The BinaryHeap with reverse effectively makes it a min heap. Want the paths to be sorted based
// on their Ordering. The best path evaluates to "less than"
struct BgpTableEntry<'a> {
    paths: BinaryHeap<Reverse<&'a PathAttributeTableEntry>>,
    changed: bool,
}
impl BgpTableEntry<'_> {
    fn new() -> Self {
        todo!()
    }
}

// Will be generic over AFI (v4/v6)
pub(crate) struct BgpTable<'a, A> {
    table: HashMap<A, BgpTableEntry<'a>>
}
impl<'a, A> BgpTable<'a, A> {
    pub fn insert(update_msg: Update, attr_table: &mut PathAttributeTable) {
        // Inserts a path into the BGP table and, implicitly, in the
        // associated path attribute table if necessary.

        // First need to generate a DecisionProcessData structure
        // based on the information.
        // Second need to extract the PA vec from
        todo!()
    }
}  
impl<'a> BgpTable<'a, Ipv4Addr> {
    pub fn new() -> Self {
        let t: HashMap<Ipv4Addr, BgpTableEntry<'a>> = HashMap::new();
        Self {
            table: t
        }
    }
}
impl<'a> BgpTable<'a, Ipv6Addr> {
    pub fn new() -> Self {
        let t: HashMap<Ipv6Addr, BgpTableEntry<'a>> = HashMap::new();
        Self {
            table: t
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_data_cmp_lp() {
        let ip_addr = Ipv4Addr::new(192, 168, 1, 1);
        let best = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 0,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ibgp,
            igp_cost: 0,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };
        let candidate = DecisionProcessData {
            local_pref: Some(100),
            as_path_len: 0,
            last_as: 0,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ibgp,
            igp_cost: 0,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };

        assert!(candidate > best);
    }
    #[test]
    fn decision_data_cmp_as_path_len() {
        let ip_addr = Ipv4Addr::new(192, 168, 1, 1);
        let best = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 5,
            last_as: 0,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ibgp,
            igp_cost: 0,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };
        let candidate = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 10,
            last_as: 0,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ibgp,
            igp_cost: 0,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };

        assert!(candidate > best);
    }
    #[test]
    fn decision_data_cmp_origin() {
        let ip_addr = Ipv4Addr::new(192, 168, 1, 1);
        let best = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 0,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ibgp,
            igp_cost: 900,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };
        let candidate = DecisionProcessData {
            local_pref: None,
            as_path_len: 0,
            last_as: 0,
            origin: 1,
            med: 0,
            route_souce: RouteSource::Ibgp,
            igp_cost: 0,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };

        assert!(candidate > best);
    }
    #[test]
    fn decision_data_cmp_med() {
        let ip_addr = Ipv4Addr::new(192, 168, 1, 1);
        let best = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ibgp,
            igp_cost: 900,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };
        let candidate = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 1000,
            route_souce: RouteSource::Ebgp,
            igp_cost: 0,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };

        assert!(candidate > best);
    }
}