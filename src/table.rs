// Holds logic for the BGP RIBs and Decision Process

use std::{
    cmp,
    cmp::Reverse,
    collections::{HashMap, BinaryHeap},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    rc::Rc,
};

use hashbrown::HashSet;

use crate::{message_types::{Nlri, Update}, path_attrs::*};

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
#[derive(Eq, PartialEq, Hash, Clone)]
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
#[derive(PartialEq, Eq, Hash, Clone)]
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
impl PathAttributeTable {
    pub fn new() -> Self {
        Self {
            table: HashSet::new()
        }
    }
    pub fn insert(&mut self, entry: PathAttributeTableEntry) -> &Rc<PathAttributeTableEntry> {
        // Checks to see if the entry exists in the table and inserts if necessary.
        // A reference to the entry is always returned.
        self.table.get_or_insert(Rc::new(entry))
    }
    pub fn remove_stale(&mut self) {
        // Checks to see if any stale entries in the table exist (aka. Rc strong counts are 1)
        // and drops them.
        self.table.retain(|rc| Rc::strong_count(rc) > 1);
    }
    pub fn len(&self) -> usize {
        self.table.len()
    }
}

// The BinaryHeap with reverse effectively makes it a min heap. Want the paths to be sorted based
// on their Ordering. The best path evaluates to "less than"
struct BgpTableEntry {
    paths: BinaryHeap<Reverse<Rc<PathAttributeTableEntry>>>,
}
impl BgpTableEntry {
    fn new(pa_entry: &Rc<PathAttributeTableEntry>) -> Self {
        // No table entry can be created without an associated path! This API assumes
        // the ref to the PA Entry is coming from the Path Attribute table (has already been inserted there).
        let mut new_path: BinaryHeap<Reverse<Rc<PathAttributeTableEntry>>> = BinaryHeap::new();
        new_path.push(Reverse(Rc::clone(pa_entry)));

        Self {
            paths: new_path
        }
    }
    fn insert(&mut self, pa_entry: &Rc<PathAttributeTableEntry>) -> bool {
        // Inserts the ref to a table entry (presumably returned from the PathAttributeTable)
        // into the local min. heap if it doesn't already exist (duplicate entry).
        // Leverage deref coercion with is_in().
        match self.is_in(pa_entry) {
            true => false,
            false => {
                self.paths.push(Reverse(Rc::clone(pa_entry)));
                true
            }
        }
    }
    fn is_in(&self, pa_entry: &PathAttributeTableEntry) -> bool {
        // Walks the heap to see if the ref already exists
        match self
            .paths
            .iter()
            .filter(|exist| exist.0.as_ref() == pa_entry)
            .count() {
                0 => false,
                _ => true
            }
    }
    fn bestpath(&self) -> &Rc<PathAttributeTableEntry> {
        // Returns the best path for this destination (aka top item in the heap)
        &self
        .paths
        .peek()
        .expect("A table entry should not exist without a path!")
        .0

    }
}

// Will be generic over AFI (v4/v6)
pub(crate) struct BgpTable<A> {
    table: HashMap<A, BgpTableEntry>,
    table_version: usize,
    pa_table: PathAttributeTable,
}
impl<A> BgpTable<A> {
    pub fn walk(&mut self, payload: Update) {
        // Inserts paths from an Update message into the BGP table and, implicitly, in the
        // associated path attribute table if necessary.

        // First need to generate a DecisionProcessData structure
        // based on the information.
        // Second need to extract the PA vec from the Update message
        todo!()
    }
}  
impl BgpTable<Ipv4Addr> {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            table_version: 0,
            pa_table: PathAttributeTable::new()
        }
    }
}
impl BgpTable<Ipv6Addr> {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            table_version: 0,
            pa_table: PathAttributeTable::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::path_attrs::{AsPath, PathAttrBuilder};

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
    #[test]
    fn decision_data_cmp_rte_src() {
        let ip_addr = Ipv4Addr::new(192, 168, 1, 1);
        let best = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ebgp,
            igp_cost: 900,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };
        let candidate = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
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
    fn decision_data_cmp_igp_cost() {
        let ip_addr = Ipv4Addr::new(192, 168, 1, 1);
        let best = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ebgp,
            igp_cost: 0,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };
        let candidate = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ebgp,
            igp_cost: 900,
            peer_id: ip_addr.clone(),
            peer_addr: IpAddr::V4(ip_addr.clone())
        };

        assert!(candidate > best);
    }
    #[test]
    fn decision_data_cmp_peer_id() {
        let best_ip_addr = Ipv4Addr::new(192, 168, 1, 1);
        let cand_ip_addr = Ipv4Addr::new(192, 168, 2, 1);
        let best = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ebgp,
            igp_cost: 0,
            peer_id: best_ip_addr.clone(),
            peer_addr: IpAddr::V4(cand_ip_addr.clone())
        };
        let candidate = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ebgp,
            igp_cost: 0,
            peer_id: cand_ip_addr.clone(),
            peer_addr: IpAddr::V4(cand_ip_addr.clone())
        };

        assert!(candidate > best);
    }
    #[test]
    fn decision_data_cmp_peer_addr_v4() {
        let best_ip_addr = Ipv4Addr::new(192, 168, 1, 1);
        let cand_ip_addr = Ipv4Addr::new(192, 168, 2, 1);
        let best = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ebgp,
            igp_cost: 0,
            peer_id: cand_ip_addr.clone(),
            peer_addr: IpAddr::V4(best_ip_addr.clone())
        };
        let candidate = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ebgp,
            igp_cost: 0,
            peer_id: cand_ip_addr.clone(),
            peer_addr: IpAddr::V4(cand_ip_addr.clone())
        };

        assert!(candidate > best);
    }
    #[test]
    fn decision_data_cmp_peer_addr_v6() {
        let best_ip_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff);
        let cand_ip_addr = Ipv6Addr::new(0, 0, 0, 0, 0x01, 0xffff, 0xffff, 0xffff);
        let peer_id = Ipv4Addr::new(192, 168, 1, 1);
        let best = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ebgp,
            igp_cost: 0,
            peer_id: peer_id.clone(),
            peer_addr: IpAddr::V6(best_ip_addr.clone())
        };
        let candidate = DecisionProcessData {
            local_pref: Some(1000),
            as_path_len: 0,
            last_as: 65000,
            origin: 0,
            med: 0,
            route_souce: RouteSource::Ebgp,
            igp_cost: 0,
            peer_id: peer_id.clone(),
            peer_addr: IpAddr::V6(cand_ip_addr.clone())
        };

        assert!(candidate > best);
    }
    fn build_pa_entry() -> PathAttributeTableEntry {
        let pa = PathAttrBuilder::<Med>::new().metric(1000).build();
        let raw_pas = vec![pa];
        let ddata = DecisionProcessData {
            local_pref: Some(100),
            as_path_len: 1,
            last_as: 65000,
            origin: 0,
            med: 1000,
            route_souce: RouteSource::Ebgp,
            igp_cost: 0,
            peer_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            peer_id: Ipv4Addr::new(192, 168, 1, 1)
        };
        PathAttributeTableEntry::new(ddata, raw_pas)
    }
    #[test]
    fn bgp_entry_insert() {
        let mut pa_table = PathAttributeTable::new();
        let pa_entry = build_pa_entry();

        // Insert into pa entry table to get ref then build a new bgp_entry
        let bgp_entry = BgpTableEntry::new(pa_table.insert(pa_entry));

        // Verify entry inserted into bgp table entry
        assert_eq!(bgp_entry.paths.len(), 1);
    }
    #[test]
    fn bgp_entry_is_in() {
        let mut pa_table = PathAttributeTable::new();
        let pa_entry = build_pa_entry();
        let pa_entry_c = pa_entry.clone();

        // Insert into pa entry table to get ref then build a new bgp_entry
        let bgp_entry = BgpTableEntry::new(pa_table.insert(pa_entry));

        // Verify entry inserted into bgp table entry matches
        assert_eq!(bgp_entry.is_in(&pa_entry_c), true);
    }
}