//! SASL password-guess limits (same idea as the API login lock, ADR-103).
//!
//! Failed attempts counted within [`WINDOW`]: per (account, client address), per account over
//! all addresses, per client address over all accounts.
//!
//! - Count at start ([`Attempts::reserve`]), give back on right password ([`Slot::success`]).
//!   Cut off or failed -> stays counted -> parallel guesses cannot all pass before a count.
//! - Accounts = device UUIDs -> one address must not lock a device out for the others.
//!   Per (account, address) limit = the tight one; other 2 wide, only stop floods
//!   (CGNAT address -> many devices behind it).
//! - Bounded tables: oldest entries dropped first when full.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Max failed attempts of one client address at one account within [`WINDOW`].
pub(crate) const MAX_PER_CLIENT_ACCOUNT: u32 = 5;
/// Max failed attempts at one account, all addresses.
pub(crate) const MAX_PER_ACCOUNT: u32 = 50;
/// Max failed attempts of one client address, all accounts.
pub(crate) const MAX_PER_CLIENT: u32 = 60;
/// Time an attempt counts.
pub(crate) const WINDOW: Duration = Duration::from_secs(15 * 60);
/// Max entries per table.
const MAX_ENTRIES: usize = 10_000;
/// Max account key length (chars). Longer -> cut (no real name that long).
const MAX_KEY: usize = 64;

/// Limit reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Locked;

#[derive(Debug, Clone, Copy)]
struct Counter {
    count: u32,
    since: Instant,
}

impl Counter {
    fn live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.since) < WINDOW
    }
}

fn count<K: Hash + Eq>(table: &HashMap<K, Counter>, key: &K, now: Instant) -> u32 {
    table
        .get(key)
        .filter(|c| c.live(now))
        .map_or(0, |c| c.count)
}

fn bump<K: Hash + Eq + Clone>(table: &mut HashMap<K, Counter>, cap: usize, key: &K, now: Instant) {
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
        let Some(oldest) = table
            .iter()
            .min_by_key(|(_, c)| c.since)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        table.remove(&oldest);
    }
    table.insert(
        key.clone(),
        Counter {
            count: 1,
            since: now,
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
    pairs: HashMap<(String, IpAddr), Counter>,
    accounts: HashMap<String, Counter>,
    clients: HashMap<IpAddr, Counter>,
}

/// Attempt counters, see [`Attempts::reserve`].
#[derive(Debug)]
pub(crate) struct Attempts {
    cap: usize,
    tables: Mutex<Tables>,
}

impl Default for Attempts {
    fn default() -> Self {
        Self::new(MAX_ENTRIES)
    }
}

/// One counted attempt. Stays counted (= failure) unless [`Slot::success`] gives it back.
#[derive(Debug)]
pub(crate) struct Slot<'a> {
    attempts: &'a Attempts,
    account: String,
    client: IpAddr,
    counted: bool,
}

impl Attempts {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            tables: Mutex::default(),
        }
    }

    /// Count an attempt of `client` at `account`. Limit already reached -> [`Locked`].
    /// `client` = connection source (see [`crate::connlimit::source`]).
    pub(crate) fn reserve(&self, account: &str, client: IpAddr) -> Result<Slot<'_>, Locked> {
        let account: String = account.chars().take(MAX_KEY).collect();
        let now = Instant::now();
        // Poisoned lock = other thread panicked mid-update of plain counters -> still usable.
        let mut t = self
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pair = (account.clone(), client);
        if count(&t.pairs, &pair, now) >= MAX_PER_CLIENT_ACCOUNT
            || count(&t.accounts, &account, now) >= MAX_PER_ACCOUNT
            || count(&t.clients, &client, now) >= MAX_PER_CLIENT
        {
            return Err(Locked);
        }
        bump(&mut t.pairs, self.cap, &pair, now);
        bump(&mut t.accounts, self.cap, &account, now);
        bump(&mut t.clients, self.cap, &client, now);
        Ok(Slot {
            attempts: self,
            account,
            client,
            counted: true,
        })
    }

    #[cfg(test)]
    fn entries(&self) -> (usize, usize, usize) {
        let t = self
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (t.pairs.len(), t.accounts.len(), t.clients.len())
    }
}

impl Slot<'_> {
    /// Right password -> attempt not counted.
    pub(crate) fn success(mut self) {
        self.counted = false;
        let mut t = self
            .attempts
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        give_back(&mut t.pairs, &(self.account.clone(), self.client));
        give_back(&mut t.accounts, &self.account);
        give_back(&mut t.clients, &self.client);
    }

    /// Attempt never checked (lookup failed) -> not counted.
    pub(crate) fn refund(self) {
        self.success();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn failures_lock_an_account_for_one_client_only() {
        let a = Attempts::default();
        for _ in 0..MAX_PER_CLIENT_ACCOUNT {
            // Dropped without `success` -> failure.
            assert!(a.reserve("dev-1", ip("203.0.113.1")).is_ok());
        }
        assert!(
            a.reserve("dev-1", ip("203.0.113.1")).is_err(),
            "locked for this client"
        );
        assert!(
            a.reserve("dev-1", ip("203.0.113.2")).is_ok(),
            "other clients may still try"
        );
        assert!(
            a.reserve("dev-2", ip("203.0.113.1")).is_ok(),
            "other accounts too"
        );
    }

    #[test]
    fn a_right_password_gives_the_attempt_back() {
        let a = Attempts::default();
        for _ in 0..50 {
            a.reserve("dev-1", ip("203.0.113.1")).unwrap().success();
        }
        assert!(a.reserve("dev-1", ip("203.0.113.1")).is_ok());
        let (p, n, c) = a.entries();
        assert_eq!((p, n, c), (1, 1, 1), "only the one failure remains");
        a.reserve("dev-2", ip("203.0.113.1")).unwrap().refund();
        assert_eq!(a.entries(), (1, 1, 1));
    }

    #[test]
    fn guessing_spread_over_addresses_is_capped_per_account() {
        let a = Attempts::default();
        let mut locked_at = None;
        for i in 0..200u32 {
            let client = ip(&format!("198.51.100.{}", i % 250 + 1));
            let client = if i >= 100 {
                ip(&format!("203.0.113.{}", i - 99))
            } else {
                client
            };
            if a.reserve("dev-1", client).is_err() {
                locked_at = Some(i);
                break;
            }
        }
        assert_eq!(locked_at, Some(MAX_PER_ACCOUNT));
    }

    #[test]
    fn one_client_is_capped_over_all_accounts() {
        let a = Attempts::default();
        let mut n = 0;
        while a.reserve(&format!("dev-{n}"), ip("203.0.113.9")).is_ok() {
            n += 1;
            assert!(n <= 1000);
        }
        assert_eq!(n, MAX_PER_CLIENT);
    }

    #[test]
    fn tables_are_bounded() {
        let a = Attempts::new(100);
        for i in 0..1000 {
            let _ = a.reserve(&format!("name-{i}"), ip("203.0.113.9"));
        }
        let (p, n, c) = a.entries();
        assert!(p <= 100 && n <= 100 && c <= 100, "{p} {n} {c}");
    }
}
