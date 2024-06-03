// Holds logic for the BGP RIBs and Decision Process

use std::{
    cmp::{self, Reverse},
    collections::{BinaryHeap, HashMap},
    hash::{Hash, Hasher},
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    rc::Rc
};
// Using hashbrown due to entry API
use hashbrown::HashSet;

use crate::{message_types::{Nlri, Update, Open, Route},
            path_attrs::*,
            comms::ReceivedRoutes,
        };

type PrefixLen = u8;

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub(crate) enum RouteSource {
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
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
struct DecisionProcessData {
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
    // Naive approach here for now for testing, will most likely have
    // a custom type that the table thread picks up that does much of this
    // function's work. 
    pub fn new(data: &ReceivedRoutes) -> Self {
        Self {
            local_pref: data.local_pref(),
            as_path_len: data.as_path_len(),
            last_as: data.last_as(),
            origin: data.origin(),
            med: data.med(),
            route_souce: data.route_source(),
            igp_cost: data.igp_cost(),
            peer_id: data.peer_id(),
            peer_addr: data.peer_addr()
        }
    }
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
// the raw Path Attribute data (for easy Update creation) in addition to a representation of the relevant
// parameters necessary for running the Decision Process. This implies some data duplication, but since some PAs
// aren't relevant for the Decision Process (and one table entry can be pointed to by many routes), this seems
// reasonable.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
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
    pub fn get_pas(&self) -> Vec<PathAttr> {
        self.raw_path_attrs.clone()
    }
    pub fn peer_id(&self) -> Ipv4Addr {
        self.decision_data.peer_id
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
struct PathAttributeTable {
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
// on their Ordering. The best path evaluates to the "smallest" path based on Ordering.
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
    fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
    fn bestpath(&self) -> &Rc<PathAttributeTableEntry> {
        // Returns the best path for this destination (aka top item in the heap)
        &self
        .paths
        .peek()
        .expect("A table entry should not exist without a path!")
        .0

    }
    fn remove(&mut self, path: &PathAttributeTableEntry) {
        // Removes a path from the BGP Table Entry as long as the peer IDs match. RFC 4271, Pg. 20.
        self.paths.retain(|x| x.0.as_ref().peer_id() != path.peer_id());
    }
    fn len(&self) -> usize {
        self.paths.len()
    }
}

// Struct to house prefixes generated from a BGP Table walk
// for future UPDATE message creation
struct AdvertisedRoutes<T> {
    _marker: PhantomData<T>,
    routes: HashMap<Vec<PathAttr>, Vec<Route>>
}
impl<T> AdvertisedRoutes<T> {
    fn new() -> Self {
        Self {_marker: PhantomData, routes: HashMap::new() }
    }
    fn len(&self) -> usize {
        self.routes.len()
    }
    fn routes(&self) -> &HashMap<Vec<PathAttr>, Vec<Route>> {
        &self.routes
    }
    fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}
impl AdvertisedRoutes<Ipv4Addr> {
    fn entry(&mut self, key: Vec<PathAttr>, prefix: Ipv4Addr, prefix_len: u8) {
        // Abstracts away the machinery of the entry API.
        // Adds or updates a given Key/Value combo. Using Vec<PathAttr> as a key should be fine since the PAs are sorted
        // deterministically in the PAT Entry, which is where they're pulled from, unchanged.
        let addr = IpAddr::V4(prefix);
        self.routes
        .entry(key)
        .and_modify(|v| v.push(Route::new(prefix_len, addr)))
        .or_insert(vec![Route::new(prefix_len, addr)]);
    }
}
// Will be generic over AFI (v4/v6)
// TO-DO: Think about how aggregation can be implemented. Maybe add a suppressed field in BGP Table Entry?
// Could potentially create a radix tree from all the destinations and use this to determine which should be suppressed?
pub(crate) struct BgpTable<A> {
    table: HashMap<(A, PrefixLen), BgpTableEntry>,
    table_version: usize,
    pa_table: PathAttributeTable,
}
impl<A> BgpTable<A> {
    pub fn increment_version(&mut self) {
        self.table_version += 1;
    }
    
    pub fn num_paths(&self) -> usize {
        // Returns number of PATHs in the BGP table, not number of destinations
        self.table
        .iter()
        .map(|(_, entry)| entry.len())
        .sum()
    }
    
    pub fn num_destinations(&self) -> usize {
        // Returns number of destinations in the BGP table
        self.table.len()
    }

    pub fn num_pa_entries(&self) -> usize {
        self.pa_table.len()
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
    
    pub fn walk(&mut self, payload: ReceivedRoutes) -> (Vec<Route>, AdvertisedRoutes<Ipv4Addr>) {
        // Inserts (and/or removes) paths received in an Update message to/from the BGP table.
        // The function returns routes that can be withdrawn along with a container holding all
        // the Nlri that would need to be advertised using different Update messages, based on changes
        // to the BGP table. 

        let ddata = DecisionProcessData::new(&payload);
        let mut adv_routes: AdvertisedRoutes<Ipv4Addr> = AdvertisedRoutes::new();
        let mut removed_routes: Vec<Route> = Vec::new();


        // Pre-emptively update the PAT and get the ref necessary to update BGP
        // table entries
        let pat_entry = PathAttributeTableEntry::new(ddata, payload.path_attrs());
        let pat_entry_ref = self.pa_table.insert(pat_entry);
        

        // First check to see if there are any new routes to be added to table. If not, immediately check to
        // see if any routes need to be withdrawn. These two operations are logically disjoint, the intersection of
        // advertised and withdrawn routes from a given Update should be the empty set.
        // RFC 4271 states that implementations should be able to catch cases where the intersection ISNT the empty set,
        // which will occur before the data reaches this algorithm.
        if let Some(new_paths) = payload.routes() {
            new_paths
            .iter()
            .filter(|dest| dest.prefix_v4().is_some()) // only allow v4
            .for_each(|dest| {
                match self.table.get_mut(&(dest.prefix_v4().expect("Filter should only allow v4 routes"), dest.length())) {
                    // If the BGP table entry exists, add path to it
                    Some(bgp_table_entry) => {
                        bgp_table_entry.insert(pat_entry_ref);
                        // If the new entry is the bestpath, add it to
                        // the container to be advertised. Entry API is amazing!
                        if bgp_table_entry.bestpath() == pat_entry_ref {
                            adv_routes.entry(pat_entry_ref.get_pas(), dest.prefix_v4().unwrap(), dest.length());
                        }
                    },
                    // Otherwise, create a new entry and insert the ref. Add to container
                    // to be advertised.
                    None => {
                        self.table.insert((dest.prefix_v4().unwrap(), dest.length()), BgpTableEntry::new(pat_entry_ref));
                        adv_routes.entry(pat_entry_ref.get_pas(), dest.prefix_v4().unwrap(), dest.length());

                    }
                }
            })
        }

        if let Some(del_paths) = payload.withdrawn_routes() {
            del_paths
            .iter()
            .filter(|dest| dest.prefix_v4().is_some()) // Only allow v4
            .for_each(|dest| {
                match self.table.get_mut(&(dest.prefix_v4().expect("Filter should only allow v4 routes"), dest.length())) {
                    // Check to see if destination is in table
                    Some(bgp_table_entry) => {
                        // Check to see if path to be removed is currently the bestpath. RFC 4271, Pg. 20
                        // states that only need to match on peer.
                        let was_best = if bgp_table_entry.bestpath().peer_id() == pat_entry_ref.peer_id() {
                            true
                        } else {false};
                        // Remove the path
                        bgp_table_entry.remove(pat_entry_ref);
                        // If resulting BGP table entry is empty, remove from table and add destination
                        // to routes to be withdrawn from peers.
                        if bgp_table_entry.is_empty() {
                           _ = self.table.remove(&(dest.prefix_v4().unwrap(), dest.length()));
                           removed_routes.push(Route::new(dest.length(), IpAddr::V4(dest.prefix_v4().unwrap())))
                        } else if was_best { // Otherwise, if new bestpath, add to adv routes container
                            adv_routes.entry(bgp_table_entry.bestpath().get_pas(), dest.prefix_v4().unwrap(), dest.length());
                        }
                    },
                    // Do nothing in None case
                    None => {
                        ();
                    }
                }
            });

        }
        // Clean up the PA table
        self.pa_table.remove_stale();

        // Increment the table version if the table changed (bestpaths changed and/or destinations removed.)
        if !removed_routes.is_empty() || !adv_routes.is_empty() {
            self.increment_version();
        }

        (removed_routes, adv_routes)
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
    use rand::{seq::SliceRandom, Rng};
    use crate::{comms::MockReceivedRoutesBuilder, message_types::Route};

    use super::*;


    // Setup Functions
    
    fn build_pa_entry(med_val: u32, origin: OriginValue) -> PathAttributeTableEntry {
        let pa = PathAttrBuilder::<Med>::new().metric(med_val).build();
        let pa2 = PathAttrBuilder::<Origin>::new().origin(origin.clone()).build();
        let mut raw_pas = vec![pa, pa2];
        // Randomly shuffle the PA vector since it should be sorted deterministically by
        // its generating function.
        let mut rng = rand::thread_rng();
        raw_pas.shuffle(&mut rng);

        let ddata = DecisionProcessData {
            local_pref: Some(100),
            as_path_len: 1,
            last_as: 65000,
            origin: origin.into(),
            med: med_val,
            route_souce: RouteSource::Ebgp,
            igp_cost: 0,
            peer_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            peer_id: Ipv4Addr::new(192, 168, 1, 1)
        };
        PathAttributeTableEntry::new(ddata, raw_pas)
    }

    fn generate_routes_v4(num_routes: usize) -> Vec<Route> {
        let mut rng = rand::thread_rng();
        let c = |_| {
                let addr = Ipv4Addr::new(rng.gen_range(1..=223),
                             rng.gen_range(0..=255),
                             rng.gen_range(0..=255),
                             rng.gen_range(0..=254));
                Route::new(rng.gen_range(1..=32), IpAddr::V4(addr))
        };
        (1..=num_routes).map(c).collect()
    }

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


    // Path Attribute Table Tests
    #[test]
    fn test_pat_entry_eq () {
        let pate_1 = build_pa_entry(100, OriginValue::Igp);
        let pate_2 = build_pa_entry(100, OriginValue::Igp);
        let pate_3 = build_pa_entry(300, OriginValue::Egp);

        assert_eq!(pate_1, pate_2);
        assert_ne!(pate_1, pate_3);
    }
    #[test]
    fn test_pat_remove_stale() {
        let mut pa_table = PathAttributeTable::new();
        let pa_entry = build_pa_entry(1000, OriginValue::Igp);

        // Add entry to table then clone to increase strong count
        let rc_ref = pa_table.insert(pa_entry);
        let _cloned = Rc::clone(rc_ref);

        // Run remove stale; nothing should get removed since strong counts should be two
        pa_table.remove_stale();
        assert_eq!(pa_table.len(), 1);
    }

    // BGP Table Entry Tests
    #[test]
    fn bgp_entry_insert() {
        let mut pa_table = PathAttributeTable::new();
        let pa_entry = build_pa_entry(1000, OriginValue::Egp);
        let pa_entry_c = pa_entry.clone();

        // Insert into pa entry table to get ref then build a new bgp_entry
        let bgp_entry = BgpTableEntry::new(pa_table.insert(pa_entry));

        // Verify entry was inserted into bgp table entry and is the same
        assert_eq!(bgp_entry.paths.len(), 1);
        assert_eq!(bgp_entry.is_in(&pa_entry_c), true);
    }
    #[test]
    fn bgp_entry_is_in() {
        let mut pa_table = PathAttributeTable::new();
        let pa_entry = build_pa_entry(1000, OriginValue::Igp);
        let pa_entry_c = pa_entry.clone();
        let wrong_pa_entry = build_pa_entry(900, OriginValue::Incomplete);

        // Insert into pa entry table to get ref then build a new bgp_entry
        let bgp_entry = BgpTableEntry::new(pa_table.insert(pa_entry));

        // Verify entry inserted into bgp table entry matches
        assert_eq!(bgp_entry.is_in(&pa_entry_c), true);
        assert_eq!(bgp_entry.is_in(&wrong_pa_entry), false);
    }
    #[test]
    fn test_bestpath() {
        let mut pa_table = PathAttributeTable::new();
        let pa_entry = build_pa_entry(1000, OriginValue::Incomplete);
        let best_pa_entry = build_pa_entry(10, OriginValue::Igp);
        let best_pa_entry_c = best_pa_entry.clone();

        // Insert both pa entries into PA table to get ref then build a new bgp_entry
        let mut bgp_entry = BgpTableEntry::new(pa_table.insert(pa_entry));
        bgp_entry.insert(pa_table.insert(best_pa_entry));

        // Check to make sure best path is the one with lower med
        let best_rc = Rc::new(best_pa_entry_c);
        assert_eq!(bgp_entry.paths.len(), 2);
        assert_eq!(bgp_entry.bestpath(), &best_rc)
    }


    // BGP Table Tests
    #[test]
    fn bgp_table_single_walk_add_only() {
        // Generate routes and PAs, will be used for two separate peers to diversify BGP table
        let med = 1000u32;
        let origin = OriginValue::Incomplete;
        let mut routes = generate_routes_v4(100000);
        // Need to sort and dedup vec to know exact number of destinations
        routes.sort();
        routes.dedup();
        let pa = PathAttrBuilder::<Med>::new().metric(med).build();
        let pa2 = PathAttrBuilder::<Origin>::new().origin(origin).build();
        let pas = vec![pa, pa2];
        
        // Create the payload
        let rxr = MockReceivedRoutesBuilder::new(Some(routes.clone()), None, pas.clone()).build();

        // Create table and add prefixes
        let mut table = BgpTable::<Ipv4Addr>::new();
        _ = table.walk(rxr);

        // Now verify the number of paths/destinations/PAT entries
        assert_eq!(table.num_destinations(), routes.len());
        assert_eq!(table.num_pa_entries(), 1);
        assert_eq!(table.num_paths(), routes.len());

    }

    #[test]
    fn bgp_table_walk_multi_add_only() {
        // Generate routes and PAs, will be used for two separate peers to diversify BGP table
        let med = 1000u32;
        let origin = OriginValue::Incomplete;
        let mut routes = generate_routes_v4(100000);
        // Need to sort and dedup vec to know exact number of destinations
        routes.sort();
        routes.dedup();
        let pa = PathAttrBuilder::<Med>::new().metric(med).build();
        let pa2 = PathAttrBuilder::<Origin>::new().origin(origin).build();
        let pas = vec![pa, pa2];
        let peer1_id = Ipv4Addr::new(10, 2, 2, 1);

        // Generate two different rx routes messages with the same information other than a different peer
        // id.
        let rxr1 = MockReceivedRoutesBuilder::new(Some(routes.clone()),None, pas.clone()).peer_id(peer1_id).build();
        let rxr2 = MockReceivedRoutesBuilder::new(Some(routes.clone()), None, pas.clone()).build();

        // Create new BGP table
        let mut table = BgpTable::<Ipv4Addr>::new();

        // Walk over routes and install into table
        _ = table.walk(rxr1);
        _ = table.walk(rxr2);

        assert_eq!(table.num_destinations(), routes.len());
        assert_eq!(table.num_pa_entries(), 2);
        assert_eq!(table.num_paths(), 2 * routes.len());
    }

    #[test]
    fn bgp_table_single_walk_add_remove() {
        // Generate routes and PAs, will be used for two separate peers to diversify BGP table
        let med = 1000u32;
        let origin = OriginValue::Incomplete;
        let mut routes = generate_routes_v4(100000);
        // Need to sort and dedup vec to know exact number of destinations
        routes.sort();
        routes.dedup();
        let pa = PathAttrBuilder::<Med>::new().metric(med).build();
        let pa2 = PathAttrBuilder::<Origin>::new().origin(origin).build();
        let pas = vec![pa, pa2];

        // Generate two different rx routes messages with the same information other than a different peer
        // id.
        let rxr_adv = MockReceivedRoutesBuilder::new(Some(routes.clone()),None, pas.clone()).build();
        let rxr_withdrawn = MockReceivedRoutesBuilder::new(None, Some(routes.clone()), pas.clone()).build();

        // Create new BGP table
        let mut table = BgpTable::<Ipv4Addr>::new();

        // Walk over routes and install into table
        _ = table.walk(rxr_adv);

        // Should have 1000 destinations and only one PAT entry
        assert_eq!(table.num_destinations(), routes.len());
        assert_eq!(table.num_pa_entries(), 1);
        assert_eq!(table.num_paths(), routes.len());

        // Now walk over the table and remove all the routes that were previously advertised
        _ = table.walk(rxr_withdrawn);

        assert_eq!(table.num_destinations(), 0);
        assert_eq!(table.num_pa_entries(), 0);
        assert_eq!(table.num_paths(), 0);

    }
    #[test]
    fn bgp_table_multi_walk_add_remove() {
        // Generate routes and PAs, will be used for two separate peers to diversify BGP table
        let med = 1000u32;
        let origin = OriginValue::Incomplete;
        let mut routes = generate_routes_v4(100000);
        // Need to sort and dedup vec to know exact number of destinations
        routes.sort();
        routes.dedup();
        let pa = PathAttrBuilder::<Med>::new().metric(med).build();
        let pa2 = PathAttrBuilder::<Origin>::new().origin(origin).build();
        let pas = vec![pa, pa2];
        let peer1_id = Ipv4Addr::new(10, 2, 2, 1);


        // Generate two different rx routes messages with the same information other than a different peer
        // id.
        let rxr1_adv = MockReceivedRoutesBuilder::new(Some(routes.clone()),None, pas.clone()).build();
        let rxr1_withdrawn = MockReceivedRoutesBuilder::new(None, Some(routes.clone()), pas.clone()).build();
        let rxr2_adv = MockReceivedRoutesBuilder::new(Some(routes.clone()),None, pas.clone()).peer_id(peer1_id).build();


        // Create new BGP table
        let mut table = BgpTable::<Ipv4Addr>::new();

        // Walk over routes and install into table
        _ = table.walk(rxr1_adv);
        _ = table.walk(rxr2_adv);

        // Should have 1000 destinations and only two PAT entry
        assert_eq!(table.num_destinations(), routes.len());
        assert_eq!(table.num_pa_entries(), 2);
        assert_eq!(table.num_paths(), 2 * routes.len());

        // Now walk over the table and remove all the paths that were previously advertised in rxr1
        _ = table.walk(rxr1_withdrawn);

        assert_eq!(table.num_destinations(), routes.len());
        assert_eq!(table.num_pa_entries(), 1);
        assert_eq!(table.num_paths(), routes.len());
    }
    #[test]
    fn bgp_table_adv_routes_single_pa() {
        // Will test adv routes output when only
        // expecting the AdvertisedRoutes struct to have length 1
        // (aka only one Update message to be created).
        
        // Generate route and PA
        let med = 1000u32;
        let origin = OriginValue::Incomplete;
        let mut routes = generate_routes_v4(100);
        // Need to sort and dedup vec to know exact number of destinations
        routes.sort();
        routes.dedup();
        let pa = PathAttrBuilder::<Med>::new().metric(med).build();
        let pa2 = PathAttrBuilder::<Origin>::new().origin(origin).build();
        let pas = vec![pa, pa2];

        // Generate payload and table and add routes to the table
        let rxr = MockReceivedRoutesBuilder::new(Some(routes.clone()),None, pas.clone()).build();
        let mut table = BgpTable::<Ipv4Addr>::new();
        let (_, adv_routes) = table.walk(rxr);

        assert_eq!(adv_routes.len(), 1);
        for (k, v) in adv_routes.routes().iter() {
            assert_eq!(k[0].attr_type_code(), 1); // Checking vec sorting
            assert_eq!(k[1].attr_type_code(), 4); // Checking vec sorting
            assert_eq!(v.len(), routes.len());
        }

    }
}