//! Guess limits (ADR-103): tries at one name (password, second-factor code) per [`WINDOW`].
//!
//! - **Atomic**: [`Attempts::reserve`] counts *before* the slow check, under one lock
//!   (Argon2 hash: up to 10 s on a busy server) -> parallel requests cannot all pass first.
//!   Given back when no check was made or the answer was right ([`Slot::refund`],
//!   [`Slot::success`]). Slot just dropped -> stays a failure -> request cut off half-way
//!   counts too.
//! - **Per client + per name**: max [`MAX_PER_CLIENT`] from one client address at one name,
//!   max [`MAX_PER_NAME`] at one name over all addresses. One attacker locks the name only
//!   for own address; guessing from many addresses still capped.
//! - **Bounded**: max `cap` entries per table. Account names kept apart from made-up names
//!   (attacker sends 1000s); under pressure made-up ones dropped first -> no flood resets
//!   counters of real accounts.
//!
//! Same type, 2 separate tables: login (`AppState::login_attempts`, key = typed name) and
//! two-factor account screens (`AppState::totp_attempts`, key = account id)
//! -> name typed at login cannot lock an account screen, nor the reverse.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Max attempts from one client address at one name per [`WINDOW`].
pub(crate) const MAX_PER_CLIENT: u32 = 5;
/// Max attempts from all client addresses together at one name per [`WINDOW`].
pub(crate) const MAX_PER_NAME: u32 = 50;
/// Time an attempt counts.
pub(crate) const WINDOW: Duration = Duration::from_secs(15 * 60);
/// Max entries per table.
pub(crate) const MAX_ENTRIES: usize = 10_000;
/// Max chars of a name key; longer names cut.
const MAX_NAME_KEY: usize = 128;

/// Name locked: too many attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Locked;

#[derive(Debug, Clone, Copy)]
struct Counter {
    count: u32,
    since: Instant,
    /// Name is an account (used only in the per-client table: both kinds there).
    known: bool,
}

impl Counter {
    fn live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.since) < WINDOW
    }
}

/// Count one attempt at `key`; max `cap` entries in the table.
fn bump<K: Hash + Eq + Clone>(
    table: &mut HashMap<K, Counter>,
    cap: usize,
    key: &K,
    known: bool,
    now: Instant,
) {
    if let Some(c) = table.get_mut(key)
        && c.live(now)
    {
        c.count += 1;
        return;
    }
    table.remove(key);
    if table.len() >= cap {
        table.retain(|_, c| c.live(now));
    }
    while table.len() >= cap {
        // Made-up names first, oldest first.
        let Some(victim) = table
            .iter()
            .min_by_key(|(_, c)| (c.known, c.since))
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        table.remove(&victim);
    }
    table.insert(
        key.clone(),
        Counter {
            count: 1,
            since: now,
            known,
        },
    );
}

fn give_back<K: Hash + Eq>(table: &mut HashMap<K, Counter>, key: &K) {
    if let Some(c) = table.get_mut(key) {
        c.count = c.count.saturating_sub(1);
        if c.count == 0 {
            table.remove(key);
        }
    }
}

#[derive(Debug, Default)]
struct Tables {
    /// Per (name, client address), all names.
    pairs: HashMap<(String, String), Counter>,
    /// Per name over all addresses, account names.
    known: HashMap<String, Counter>,
    /// Same, names that are not accounts.
    unknown: HashMap<String, Counter>,
}

impl Tables {
    fn names(&mut self, known: bool) -> &mut HashMap<String, Counter> {
        if known {
            &mut self.known
        } else {
            &mut self.unknown
        }
    }
}

/// Attempt counters, see [`Attempts::reserve`].
#[derive(Debug)]
pub(crate) struct Attempts {
    cap: usize,
    tables: Mutex<Tables>,
}

impl Attempts {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            tables: Mutex::default(),
        }
    }

    /// Table key of a name: first [`MAX_NAME_KEY`] chars.
    pub(crate) fn name_key(name: &str) -> String {
        name.chars().take(MAX_NAME_KEY).collect()
    }

    /// Count an attempt by `client` at `name` -> slot to settle it.
    /// Client or name out of attempts -> [`Locked`], nothing counted.
    /// `known` = name is an account. Call *before* the slow check.
    pub(crate) fn reserve(
        &self,
        name: &str,
        client: &str,
        known: bool,
        now: Instant,
    ) -> Result<Slot<'_>, Locked> {
        let (name, client) = (Self::name_key(name), client.to_owned());
        let pair = (name.clone(), client.clone());
        let Ok(mut t) = self.tables.lock() else {
            // Poisoned lock = another request panicked -> refuse, do not guess.
            return Err(Locked);
        };
        let full = |c: Option<&Counter>, max: u32| c.is_some_and(|c| c.live(now) && c.count >= max);
        if full(t.pairs.get(&pair), MAX_PER_CLIENT) || full(t.names(known).get(&name), MAX_PER_NAME)
        {
            return Err(Locked);
        }
        bump(&mut t.pairs, self.cap, &pair, known, now);
        bump(t.names(known), self.cap, &name, known, now);
        drop(t);
        Ok(Slot {
            owner: self,
            name,
            client,
            known,
        })
    }

    /// Drop all attempts at `name`, all clients (account state changed: two-factor reset).
    pub(crate) fn forget(&self, name: &str) {
        let name = Self::name_key(name);
        if let Ok(mut t) = self.tables.lock() {
            t.pairs.retain(|(n, _), _| *n != name);
            t.known.remove(&name);
            t.unknown.remove(&name);
        }
    }

    #[cfg(test)]
    pub(crate) fn sizes(&self) -> (usize, usize, usize) {
        self.tables.lock().map_or((0, 0, 0), |t| {
            (t.pairs.len(), t.known.len(), t.unknown.len())
        })
    }
}

/// Counted attempt, not settled yet.
///
/// [`Slot::success`] = answer right. [`Slot::refund`] = no answer checked (server busy,
/// storage failed, or person only asked for the second factor). Drop = count kept = wrong.
#[derive(Debug)]
pub(crate) struct Slot<'a> {
    owner: &'a Attempts,
    name: String,
    client: String,
    known: bool,
}

impl Slot<'_> {
    /// Answer right -> client's tries at this name reset + attempt off the name total.
    pub(crate) fn success(self) {
        if let Ok(mut t) = self.owner.tables.lock() {
            t.pairs.remove(&(self.name.clone(), self.client.clone()));
            give_back(t.names(self.known), &self.name);
        }
    }

    /// Nothing checked -> attempt given back.
    pub(crate) fn refund(self) {
        if let Ok(mut t) = self.owner.tables.lock() {
            give_back(&mut t.pairs, &(self.name.clone(), self.client.clone()));
            give_back(t.names(self.known), &self.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(a: &Attempts, name: &str, client: &str, known: bool, now: Instant) {
        for _ in 0..MAX_PER_CLIENT {
            drop(a.reserve(name, client, known, now).expect("room"));
        }
    }

    #[test]
    fn attempts_are_counted_at_reservation_so_concurrent_ones_cannot_exceed_the_limit() {
        let a = Attempts::new(100);
        let t0 = Instant::now();
        // Nothing settled yet -> all 6 asks while the checks still run.
        let mut held = Vec::new();
        for _ in 0..MAX_PER_CLIENT {
            held.push(a.reserve("kim", "1.1.1.1", true, t0).expect("room"));
        }
        assert_eq!(a.reserve("kim", "1.1.1.1", true, t0).err(), Some(Locked));
        // Right answer -> client's tries cleared -> no lock.
        held.pop().expect("slot").success();
        assert!(a.reserve("kim", "1.1.1.1", true, t0).is_ok());
    }

    #[test]
    fn real_threads_cannot_get_past_the_limit_together() {
        let a = std::sync::Arc::new(Attempts::new(100));
        let t0 = Instant::now();
        let passed = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let threads: Vec<_> = (0..64)
            .map(|_| {
                let (a, passed) = (a.clone(), passed.clone());
                std::thread::spawn(move || {
                    if let Ok(slot) = a.reserve("kim", "1.1.1.1", true, t0) {
                        passed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        drop(slot); // wrong answer
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("thread");
        }
        assert_eq!(
            passed.load(std::sync::atomic::Ordering::SeqCst),
            MAX_PER_CLIENT
        );
    }

    #[test]
    fn a_refund_gives_the_attempt_back() {
        let a = Attempts::new(100);
        let t0 = Instant::now();
        for _ in 0..20 {
            a.reserve("kim", "1.1.1.1", true, t0)
                .expect("room")
                .refund();
        }
        assert_eq!(a.sizes(), (0, 0, 0), "nothing is left of refunded attempts");
        lock(&a, "kim", "1.1.1.1", true, t0);
        assert_eq!(a.reserve("kim", "1.1.1.1", true, t0).err(), Some(Locked));
    }

    #[test]
    fn one_client_cannot_lock_a_name_for_the_others() {
        let a = Attempts::new(100);
        let t0 = Instant::now();
        lock(&a, "kim", "1.1.1.1", true, t0);
        assert_eq!(a.reserve("kim", "1.1.1.1", true, t0).err(), Some(Locked));
        assert!(
            a.reserve("kim", "2.2.2.2", true, t0).is_ok(),
            "another address is not locked"
        );
        assert!(
            a.reserve("lee", "1.1.1.1", true, t0).is_ok(),
            "another name is not locked"
        );
        // Window over -> allowed again, count from 0.
        let later = t0 + WINDOW + Duration::from_secs(1);
        assert!(a.reserve("kim", "1.1.1.1", true, later).is_ok());
    }

    #[test]
    fn many_clients_together_are_capped_per_name() {
        let a = Attempts::new(10_000);
        let t0 = Instant::now();
        // 1 try each from many addresses -> no address locked.
        for i in 0..MAX_PER_NAME {
            let client = format!("10.0.{}.{}", i / 250, i % 250);
            drop(a.reserve("kim", &client, true, t0).expect("room"));
        }
        assert_eq!(
            a.reserve("kim", "192.0.2.1", true, t0).err(),
            Some(Locked),
            "the ceiling over all addresses"
        );
        assert!(
            a.reserve("lee", "192.0.2.1", true, t0).is_ok(),
            "other names are not hurt"
        );
        // Right answer -> own attempt off the total.
        let b = Attempts::new(10_000);
        for i in 0..MAX_PER_NAME - 1 {
            drop(b.reserve("kim", &format!("c{i}"), true, t0).expect("room"));
        }
        b.reserve("kim", "me", true, t0).expect("room").success();
        assert!(b.reserve("kim", "me", true, t0).is_ok());
    }

    #[test]
    fn names_that_are_not_accounts_are_limited_the_same_way() {
        let a = Attempts::new(100);
        let t0 = Instant::now();
        lock(&a, "ghost", "1.1.1.1", false, t0);
        assert_eq!(a.reserve("ghost", "1.1.1.1", false, t0).err(), Some(Locked));
        assert!(a.reserve("ghost", "2.2.2.2", false, t0).is_ok());
    }

    #[test]
    fn tables_stay_bounded_and_made_up_names_go_first() {
        let cap = 100;
        let a = Attempts::new(cap);
        let t0 = Instant::now();
        // alice: total nearly used up. bob: one client locked.
        for i in 0..MAX_PER_NAME - 1 {
            drop(
                a.reserve("alice", &format!("c{i}"), true, t0)
                    .expect("room"),
            );
        }
        lock(&a, "bob", "6.6.6.6", true, t0);
        // Flood of made-up names from made-up addresses, far past the cap
        // (table room: 50 account entries + 50 of the flood).
        for i in 0..(cap * 20) {
            let at = t0 + Duration::from_millis(1 + u64::try_from(i).expect("small"));
            drop(
                a.reserve(&format!("n{i}"), &format!("a{i}"), false, at)
                    .expect("room"),
            );
            let (pairs, known, unknown) = a.sizes();
            assert!(
                pairs <= cap && known <= cap && unknown <= cap,
                "{pairs} {known} {unknown}"
            );
        }
        // Account counters survived the flood.
        let at = t0 + Duration::from_secs(5);
        assert!(a.reserve("alice", "x", true, at).is_ok());
        assert_eq!(
            a.reserve("alice", "y", true, at).err(),
            Some(Locked),
            "alice's total still counts the earlier attempts"
        );
        assert_eq!(
            a.reserve("bob", "6.6.6.6", true, at).err(),
            Some(Locked),
            "bob stays locked for the address that locked him"
        );
        // No flood entries in the account name table.
        let (_, known, unknown) = a.sizes();
        assert_eq!(known, 2);
        assert!(unknown <= cap);
    }

    #[test]
    fn long_names_count_as_their_first_characters() {
        let a = Attempts::new(100);
        let t0 = Instant::now();
        let long = "x".repeat(MAX_NAME_KEY * 3);
        for i in 0..MAX_PER_CLIENT {
            drop(
                a.reserve(&format!("{long}{i}"), "c", false, t0)
                    .expect("room"),
            );
        }
        assert_eq!(
            a.reserve(&format!("{long}y"), "c", false, t0).err(),
            Some(Locked)
        );
    }

    #[test]
    fn forgetting_a_name_clears_every_client() {
        let a = Attempts::new(100);
        let t0 = Instant::now();
        lock(&a, "kim", "1.1.1.1", true, t0);
        lock(&a, "kim", "2.2.2.2", true, t0);
        lock(&a, "lee", "1.1.1.1", true, t0);
        a.forget("kim");
        assert!(a.reserve("kim", "1.1.1.1", true, t0).is_ok());
        assert!(a.reserve("kim", "2.2.2.2", true, t0).is_ok());
        assert_eq!(a.reserve("lee", "1.1.1.1", true, t0).err(), Some(Locked));
    }
}
