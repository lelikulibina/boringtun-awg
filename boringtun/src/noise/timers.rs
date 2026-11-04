// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::errors::WireGuardError;
use crate::noise::{Tunn, TunnResult};
use std::convert::TryFrom;
use std::ops::{Index, IndexMut};

use super::amnezia::AmneziaConfig;
use rand_core::{OsRng, RngCore};
use std::time::Duration;

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
pub(crate) const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub(crate) const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum TimerName {
    /// Current time, updated by timer events and each call to `update_timers`
    TimeCurrent,
    /// Time when last handshake was completed
    TimeSessionEstablished,
    /// Time the last attempt for a new handshake began
    TimeLastHandshakeStarted,
    /// Time we last received and authenticated a packet
    TimeLastPacketReceived,
    /// Time we last send a packet
    TimeLastPacketSent,
    /// Time we last received and authenticated a DATA packet
    TimeLastDataPacketReceived,
    /// Time we last send a DATA packet
    TimeLastDataPacketSent,
    /// Time we last received a cookie
    TimeCookieReceived,
    /// Time we last sent persistent keepalive
    TimePersistentKeepalive,
    Top,
}

use self::TimerName::*;

#[derive(Debug)]
pub struct Timers {
    /// Is the owner of the timer the initiator or the responder for the last handshake?
    is_initiator: bool,
    /// Start time of the tunnel
    time_started: Instant,
    timers: [Duration; TimerName::Top as usize],
    pub(super) session_timers: [Duration; super::N_SESSIONS],
    /// Last completed handshake timestamp relative to time_started. Unlike
    /// session keys, the UAPI keeps this value after key material expires.
    last_handshake: Option<Duration>,
    /// Deadline for the first authenticated-data-send inactivity timer.
    /// Subsequent data sends do not move it until an authenticated packet arrives.
    pub(super) new_handshake_deadline: Option<Duration>,
    /// Deadline for the first authenticated-data-receive keepalive timer.
    /// Further data receives while pending request one additional keepalive.
    pub(super) send_keepalive_deadline: Option<Duration>,
    need_another_keepalive: bool,
    /// Mirrors upstream's one-shot keepKeyFreshReceiving guard.
    sent_last_minute_handshake: bool,
    /// Deferred until update_timers can emit the handshake datagram.
    rekey_due_on_receive: bool,
    persistent_keepalive_range: (u32, u32),
    persistent_keepalive_interval: u32,
    persistent_keepalive_deadline: Option<Duration>,
    /// Should this timer call reset rr function (if not a shared rr instance)
    pub(super) should_reset_rr: bool,
    timer_ranges: [(u32, u32); 5],
    rekey_after_time: Duration,
    rekey_timeout: Duration,
    pub(super) reject_after_time: Duration,
    keepalive_timeout: Duration,
    keepalive_timeout_max: Duration,
    new_handshake_timeout: Duration,
    pub(super) max_handshake_attempts: u32,
    pub(super) handshake_attempts: u32,
    handshake_retry_jitter: Duration,
    new_handshake_jitter: Duration,
}

impl Timers {
    pub(super) fn new(
        persistent_keepalive: Option<u16>,
        reset_rr: bool,
        amnezia: &AmneziaConfig,
    ) -> Timers {
        let mut timers = Timers {
            is_initiator: false,
            time_started: Instant::now(),
            timers: Default::default(),
            session_timers: Default::default(),
            last_handshake: None,
            new_handshake_deadline: None,
            send_keepalive_deadline: None,
            need_another_keepalive: false,
            sent_last_minute_handshake: false,
            rekey_due_on_receive: false,
            persistent_keepalive_range: {
                let interval = u32::from(persistent_keepalive.unwrap_or(0));
                (interval, interval)
            },
            persistent_keepalive_interval: u32::from(persistent_keepalive.unwrap_or(0)),
            persistent_keepalive_deadline: persistent_keepalive
                .filter(|interval| *interval > 0)
                .map(|interval| Duration::from_secs(u64::from(interval))),
            should_reset_rr: reset_rr,
            timer_ranges: [
                amnezia.rekey_after_time,
                amnezia.rekey_timeout,
                amnezia.reject_after_time,
                amnezia.keepalive_timeout,
                amnezia.max_handshake_attempts,
            ],
            rekey_after_time: REKEY_AFTER_TIME,
            rekey_timeout: REKEY_TIMEOUT,
            reject_after_time: REJECT_AFTER_TIME,
            keepalive_timeout: KEEPALIVE_TIMEOUT,
            keepalive_timeout_max: KEEPALIVE_TIMEOUT,
            new_handshake_timeout: KEEPALIVE_TIMEOUT + REKEY_TIMEOUT,
            max_handshake_attempts: 18,
            handshake_attempts: 0,
            handshake_retry_jitter: Duration::ZERO,
            new_handshake_jitter: Duration::ZERO,
        };
        timers.max_handshake_attempts = timers.pick_range(4, 18);
        timers
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear(&mut self) {
        let now = Instant::now().duration_since(self.time_started);
        for t in &mut self.timers[..] {
            *t = now;
        }
        self.new_handshake_deadline = None;
        self.send_keepalive_deadline = None;
        self.need_another_keepalive = false;
        self.sent_last_minute_handshake = false;
        self.rekey_due_on_receive = false;
        self.handshake_attempts = 0;
    }

    fn range_min(&self, idx: usize, fallback: u32) -> u32 {
        let (min, max) = self.timer_ranges[idx];
        if min == 0 && max == 0 {
            fallback
        } else {
            min
        }
    }

    fn range_max(&self, idx: usize, fallback: u32) -> u32 {
        let (min, max) = self.timer_ranges[idx];
        if min == 0 && max == 0 {
            fallback
        } else {
            max
        }
    }

    fn pick_range(&self, idx: usize, fallback: u32) -> u32 {
        let (min, max) = self.timer_ranges[idx];
        if min == 0 && max == 0 {
            return fallback;
        }
        if min >= max {
            return min;
        }
        let mut rng = OsRng;
        loop {
            if let Some(selected) = Self::map_range_sample(min, max, rng.next_u32()) {
                return selected;
            }
        }
    }

    /// Map one uniformly distributed u32 sample into an inclusive range.
    /// A missing result means the sample is in the rejection tail needed to
    /// avoid modulo bias. The u64 width represents the complete u32 domain.
    fn map_range_sample(min: u32, max: u32, sample: u32) -> Option<u32> {
        if min >= max {
            return Some(min);
        }

        let width = max as u64 - min as u64 + 1;
        let zone = (1u64 << 32) / width * width;
        let value = sample as u64;
        if value >= zone {
            return None;
        }

        Some(min + (value % width) as u32)
    }

    /// Sample the upstream 0..=333 ms jitter range without modulo bias.
    fn random_jitter() -> Duration {
        loop {
            if let Some(milliseconds) = Self::map_range_sample(0, 333, OsRng.next_u32()) {
                return Duration::from_millis(milliseconds as u64);
            }
        }
    }

    /// Select a fresh retry budget at peer start and after a successful handshake.
    /// Upstream keeps the selected budget unchanged throughout a handshake attempt cycle.
    fn select_new_handshake_budget(&mut self) {
        self.handshake_attempts = 0;
        self.max_handshake_attempts = self.pick_range(4, 18);
    }

    fn pick_persistent_keepalive_interval(&self) -> u32 {
        let (min, max) = self.persistent_keepalive_range;
        if min >= max {
            return min;
        }
        loop {
            if let Some(value) = Self::map_range_sample(min, max, OsRng.next_u32()) {
                return value;
            }
        }
    }

    fn reset_persistent_keepalive(&mut self, now: Duration) {
        if self.persistent_keepalive_range == (0, 0) {
            self.persistent_keepalive_interval = 0;
            self.persistent_keepalive_deadline = None;
            return;
        }
        let interval = self.pick_persistent_keepalive_interval();
        self.persistent_keepalive_interval = interval;
        self.persistent_keepalive_deadline = Some(now + Duration::from_secs(u64::from(interval)));
    }
}

impl Index<TimerName> for Timers {
    type Output = Duration;
    fn index(&self, index: TimerName) -> &Duration {
        &self.timers[index as usize]
    }
}

impl IndexMut<TimerName> for Timers {
    fn index_mut(&mut self, index: TimerName) -> &mut Duration {
        &mut self.timers[index as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::amnezia::AmneziaConfig;

    #[test]
    fn timer_range_selection_is_inclusive_and_honors_fixed_values() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(100, 100)
            .with_rekey_timeout(3, 3)
            .with_reject_after_time(170, 170)
            .with_keepalive_timeout(8, 8)
            .with_max_handshake_attempts(12, 12);
        let timers = Timers::new(None, false, &config);
        assert_eq!(timers.pick_range(0, 120), 100);
        assert_eq!(timers.pick_range(1, 5), 3);
        assert_eq!(timers.pick_range(2, 180), 170);
        assert_eq!(timers.pick_range(3, 10), 8);
        assert_eq!(timers.max_handshake_attempts, 12);

        let ranged = AmneziaConfig::new(0, 0, 0, 0).with_rekey_timeout(2, 5);
        let ranged_timers = Timers::new(None, false, &ranged);
        for _ in 0..256 {
            let selected = ranged_timers.pick_range(1, 5);
            assert!(
                (2..=5).contains(&selected),
                "selected {selected} outside inclusive range"
            );
        }
    }

    #[test]
    fn unset_timer_ranges_preserve_wireguard_defaults() {
        let config = AmneziaConfig::new(0, 0, 0, 0);
        let timers = Timers::new(None, false, &config);
        assert_eq!(timers.pick_range(0, 120), 120);
        assert_eq!(timers.pick_range(1, 5), 5);
        assert_eq!(timers.pick_range(2, 180), 180);
        assert_eq!(timers.pick_range(3, 10), 10);
        assert_eq!(timers.max_handshake_attempts, 18);
    }

    #[test]
    fn persistent_keepalive_updates_preserve_zero_and_disabled_semantics() {
        let config = AmneziaConfig::new(0, 0, 0, 0);
        let mut timers = Timers::new(Some(25), false, &config);
        assert_eq!(timers.persistent_keepalive_range, (25, 25));
        assert_eq!(timers.persistent_keepalive_interval, 25);
        assert_eq!(
            timers.persistent_keepalive_deadline,
            Some(Duration::from_secs(25))
        );

        timers.set_persistent_keepalive(Some(0));
        assert_eq!(timers.persistent_keepalive_range, (0, 0));
        assert_eq!(timers.persistent_keepalive_interval, 0);
        assert_eq!(timers.persistent_keepalive_deadline, None);

        timers.set_persistent_keepalive(None);
        assert_eq!(timers.persistent_keepalive_range, (0, 0));
        assert_eq!(timers.persistent_keepalive_interval, 0);

        timers.set_persistent_keepalive(Some(10));
        assert_eq!(timers.persistent_keepalive_range, (10, 10));
        assert_eq!(timers.persistent_keepalive_interval, 10);
        assert!(timers.persistent_keepalive_deadline.is_some());
    }

    #[test]
    fn persistent_keepalive_range_is_sampled_and_rearmed_on_traversal() {
        let config = AmneziaConfig::new(0, 0, 0, 0);
        let mut timers = Timers::new(None, false, &config);

        timers.set_persistent_keepalive_range((10, 20));
        assert_eq!(timers.persistent_keepalive_range, (10, 20));
        assert!(
            timers.persistent_keepalive_deadline.is_some(),
            "enabling keepalive schedules the initial send immediately"
        );

        let now = Duration::from_secs(42);
        timers.reset_persistent_keepalive(now);
        assert!((10..=20).contains(&timers.persistent_keepalive_interval));
        assert_eq!(
            timers.persistent_keepalive_deadline,
            Some(now + Duration::from_secs(u64::from(timers.persistent_keepalive_interval)))
        );

        timers.set_persistent_keepalive_range((0, 0));
        assert_eq!(timers.persistent_keepalive_range, (0, 0));
        assert_eq!(timers.persistent_keepalive_deadline, None);
    }

    #[test]
    fn random_jitter_respects_the_inclusive_333_millisecond_limit() {
        assert_eq!(Timers::map_range_sample(0, 333, 0), Some(0));
        assert_eq!(Timers::map_range_sample(0, 333, 333), Some(333));

        for _ in 0..512 {
            assert!(Timers::random_jitter() <= Duration::from_millis(333));
        }
    }

    #[test]
    fn retry_budget_selection_uses_the_current_timer_range() {
        let initial = AmneziaConfig::new(0, 0, 0, 0).with_max_handshake_attempts(2, 2);
        let replacement = AmneziaConfig::new(0, 0, 0, 0).with_max_handshake_attempts(7, 7);
        let mut timers = Timers::new(None, false, &initial);
        timers.handshake_attempts = 1;
        assert_eq!(timers.max_handshake_attempts, 2);

        timers.set_timer_ranges(&replacement);
        timers.select_new_handshake_budget();

        assert_eq!(timers.handshake_attempts, 0);
        assert_eq!(
            timers.max_handshake_attempts, 7,
            "a fresh non-retry handshake must sample the updated configured budget"
        );
    }

    #[test]
    fn replacing_timer_ranges_updates_the_live_timer_configuration() {
        let initial = AmneziaConfig::new(0, 0, 0, 0).with_rekey_timeout(2, 3);
        let replacement = AmneziaConfig::new(0, 0, 0, 0).with_rekey_timeout(7, 9);
        let mut timers = Timers::new(None, false, &initial);

        assert_eq!(timers.range_min(1, 5), 2);
        assert_eq!(timers.range_max(1, 5), 3);

        timers.set_timer_ranges(&replacement);

        assert_eq!(timers.range_min(1, 5), 7);
        assert_eq!(timers.range_max(1, 5), 9);
    }

    #[test]
    fn timer_range_validation_rejects_reversed_bounds_for_every_timer() {
        let invalid = [
            AmneziaConfig::new(0, 0, 0, 0).with_rekey_after_time(2, 1),
            AmneziaConfig::new(0, 0, 0, 0).with_rekey_timeout(2, 1),
            AmneziaConfig::new(0, 0, 0, 0).with_reject_after_time(2, 1),
            AmneziaConfig::new(0, 0, 0, 0).with_keepalive_timeout(2, 1),
            AmneziaConfig::new(0, 0, 0, 0).with_max_handshake_attempts(2, 1),
        ];

        for config in invalid {
            assert!(
                config.validate_timer_ranges().is_err(),
                "reversed timer bounds must be rejected"
            );
        }
    }

    #[test]
    fn range_sampler_maps_full_u32_domain_without_truncation() {
        assert_eq!(Timers::map_range_sample(0, u32::MAX, 0), Some(0));
        assert_eq!(Timers::map_range_sample(0, u32::MAX, 1), Some(1));
        assert_eq!(
            Timers::map_range_sample(0, u32::MAX, u32::MAX),
            Some(u32::MAX)
        );
    }

    #[test]
    fn range_sampler_rejects_modulo_bias_tail() {
        // For a range of width three, the largest u32 sample is the sole
        // value outside the largest evenly divisible sampling zone.
        assert_eq!(Timers::map_range_sample(10, 12, 0), Some(10));
        assert_eq!(Timers::map_range_sample(10, 12, 1), Some(11));
        assert_eq!(Timers::map_range_sample(10, 12, 2), Some(12));
        assert_eq!(Timers::map_range_sample(10, 12, u32::MAX), None);
    }

    #[test]
    fn range_sampler_handles_single_value_ranges() {
        assert_eq!(Timers::map_range_sample(42, 42, 0), Some(42));
        assert_eq!(Timers::map_range_sample(42, 42, u32::MAX), Some(42));
    }

    #[test]
    fn timer_range_selection_handles_the_full_u32_domain_without_overflow() {
        let config = AmneziaConfig::new(0, 0, 0, 0).with_rekey_timeout(1, u32::MAX);
        let timers = Timers::new(None, false, &config);

        for _ in 0..512 {
            let selected = timers.pick_range(1, 5);
            assert!(
                (1..=u32::MAX).contains(&selected),
                "selected {selected} outside inclusive range 1..=u32::MAX"
            );
        }
    }

    #[test]
    fn timer_ranges_include_zero_as_a_valid_configured_minimum() {
        let config = AmneziaConfig::new(0, 0, 0, 0).with_rekey_timeout(0, 1);
        let timers = Timers::new(None, false, &config);

        for _ in 0..512 {
            let selected = timers.pick_range(1, 5);
            assert!(
                (0..=1).contains(&selected),
                "selected {selected} outside inclusive range 0..=1"
            );
        }
    }

    #[test]
    fn fixed_timer_ranges_are_deterministic_for_every_timer() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(111, 111)
            .with_rekey_timeout(4, 4)
            .with_reject_after_time(177, 177)
            .with_keepalive_timeout(6, 6)
            .with_max_handshake_attempts(9, 9);
        let timers = Timers::new(None, false, &config);

        for _ in 0..32 {
            assert_eq!(timers.pick_range(0, 120), 111);
            assert_eq!(timers.pick_range(1, 5), 4);
            assert_eq!(timers.pick_range(2, 180), 177);
            assert_eq!(timers.pick_range(3, 10), 6);
            assert_eq!(timers.pick_range(4, 18), 9);
        }
        assert_eq!(timers.max_handshake_attempts, 9);
    }

    #[test]
    fn timer_range_bounds_use_wireguard_fallbacks_only_when_both_are_zero() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(0, 7)
            .with_rekey_timeout(2, 0)
            .with_reject_after_time(0, 0)
            .with_keepalive_timeout(3, 9);
        let timers = Timers::new(None, false, &config);

        assert_eq!(timers.range_min(0, 120), 0);
        assert_eq!(timers.range_max(0, 120), 7);
        assert_eq!(timers.range_min(1, 5), 2);
        assert_eq!(timers.range_max(1, 5), 0);
        assert_eq!(timers.range_min(2, 180), 180);
        assert_eq!(timers.range_max(2, 180), 180);
        assert_eq!(timers.range_min(3, 10), 3);
        assert_eq!(timers.range_max(3, 10), 9);
    }
}

impl Tunn {
    /// Mirror upstream keepKeyFreshReceiving. This runs for every authenticated
    /// transport packet, including empty keepalives, and latches the decision
    /// until a handshake completes.
    pub(super) fn timer_check_key_fresh_receiving(&mut self) {
        let now = Instant::now().duration_since(self.timers.time_started);
        self.timers.reject_after_time = Duration::from_secs(
            self.timers
                .pick_range(2, REJECT_AFTER_TIME.as_secs() as u32) as u64,
        );

        if self.timers.is_initiator() && !self.timers.sent_last_minute_handshake {
            let refresh_threshold = self.timers.reject_after_time.saturating_sub(
                Duration::from_secs(
                    self.timers.range_min(3, KEEPALIVE_TIMEOUT.as_secs() as u32) as u64,
                ) + Duration::from_secs(
                    self.timers.range_min(1, REKEY_TIMEOUT.as_secs() as u32) as u64,
                ),
            );
            let established = self.timers[TimeSessionEstablished];
            if established < now && now - established > refresh_threshold {
                self.timers.sent_last_minute_handshake = true;
                self.timers.rekey_due_on_receive = true;
            }
        }
    }

    pub(super) fn timer_tick(&mut self, timer_name: TimerName) {
        let now = Instant::now().duration_since(self.timers.time_started);
        self.timers[TimeCurrent] = now;

        match timer_name {
            TimeLastPacketReceived => {
                // Any authenticated packet from the peer cancels the inactivity
                // handshake timer, as timersAnyAuthenticatedPacketReceived does
                // in amneziawg-go. Upstream also restarts persistent keepalive
                // with a fresh sample on every authenticated traversal.
                self.timers.new_handshake_deadline = None;
                self.timers.reset_persistent_keepalive(now);
            }
            TimeLastPacketSent => {
                // Any authenticated outbound packet cancels a pending keepalive
                // and selects a fresh persistent-keepalive interval.
                self.timers.send_keepalive_deadline = None;
                self.timers.reset_persistent_keepalive(now);
            }
            TimeLastHandshakeStarted => {
                self.timers.rekey_due_on_receive = false;
                self.timers.rekey_timeout = Duration::from_secs(
                    self.timers.pick_range(1, REKEY_TIMEOUT.as_secs() as u32) as u64,
                );
                self.timers.handshake_retry_jitter = Timers::random_jitter();
            }
            TimeLastDataPacketSent => {
                self.timers.rekey_after_time = Duration::from_secs(
                    self.timers.pick_range(0, REKEY_AFTER_TIME.as_secs() as u32) as u64,
                );
                // Upstream starts this timer on the first data send after the
                // last authenticated receive; later sends do not reset it.
                if self.timers.new_handshake_deadline.is_none() {
                    // Upstream newHandshakeTimeout uses KeepaliveTimeout.Hi,
                    // plus a freshly sampled RekeyTimeout.
                    self.timers.keepalive_timeout_max = Duration::from_secs(
                        self.timers.range_max(3, KEEPALIVE_TIMEOUT.as_secs() as u32) as u64,
                    );
                    let rekey_timeout = self.timers.pick_range(1, REKEY_TIMEOUT.as_secs() as u32);
                    self.timers.new_handshake_timeout = self.timers.keepalive_timeout_max
                        + Duration::from_secs(rekey_timeout as u64);
                    self.timers.new_handshake_jitter = Timers::random_jitter();
                    self.timers.new_handshake_deadline = Some(
                        now + self.timers.new_handshake_timeout + self.timers.new_handshake_jitter,
                    );
                }
            }
            TimeLastDataPacketReceived => {
                // The first data receive starts the keepalive timer. Further
                // receives while it is pending request one more keepalive after
                // the first one, rather than moving the existing deadline.
                if self.timers.send_keepalive_deadline.is_none() {
                    self.timers.keepalive_timeout = Duration::from_secs(
                        self.timers
                            .pick_range(3, KEEPALIVE_TIMEOUT.as_secs() as u32)
                            as u64,
                    );
                    self.timers.send_keepalive_deadline = Some(now + self.timers.keepalive_timeout);
                } else {
                    self.timers.need_another_keepalive = true;
                }
            }
            _ => {}
        }

        self.timers[timer_name] = now;
    }

    pub(super) fn timer_tick_session_established(
        &mut self,
        is_initiator: bool,
        session_idx: usize,
    ) {
        self.timer_tick(TimeSessionEstablished);
        self.timers.last_handshake = Some(self.timers[TimeCurrent]);
        self.timers.session_timers[session_idx % crate::noise::N_SESSIONS] =
            self.timers[TimeCurrent];
        self.timers.is_initiator = is_initiator;
        self.timers.new_handshake_deadline = None;
        self.timers.send_keepalive_deadline = None;
        self.timers.need_another_keepalive = false;
        self.timers.sent_last_minute_handshake = false;
        self.timers.rekey_due_on_receive = false;
        self.timers.select_new_handshake_budget();
        self.timers.handshake_retry_jitter = Timers::random_jitter();
        self.pending_amnezia_junk = None;
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    fn clear_all(&mut self) {
        for session in &mut self.sessions {
            *session = None;
        }

        self.packet_queue.clear();
        self.pending_amnezia_junk = None;

        self.timers.clear();
    }

    fn update_session_timers(&mut self, time_now: Duration) {
        let reject_after = Duration::from_secs(
            self.timers.range_max(2, REJECT_AFTER_TIME.as_secs() as u32) as u64,
        );
        let timers = &mut self.timers;

        for (i, t) in timers.session_timers.iter_mut().enumerate() {
            if time_now - *t > reject_after {
                if let Some(session) = self.sessions[i].take() {
                    tracing::debug!(
                        message = "SESSION_EXPIRED(REJECT_AFTER_TIME)",
                        session = session.receiving_index
                    );
                }
                *t = time_now;
            }
        }
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let mut handshake_initiation_required = false;
        let mut keepalive_required = false;
        let mut keepalive_rearm = None;

        let time = Instant::now();

        if self.timers.should_reset_rr {
            self.rate_limiter.reset_count();
        }

        // All the times are counted from tunnel initiation, for efficiency our timers are rounded
        // to a second, as there is no real benefit to having highly accurate timers.
        let now = time.duration_since(self.timers.time_started);
        self.timers[TimeCurrent] = now;

        self.update_session_timers(now);

        if self.pending_amnezia_junk.is_some() {
            return self.advance_amnezia_junk(dst);
        }

        if self.handshake.is_expired() {
            return TunnResult::Err(WireGuardError::ConnectionExpired);
        }

        // Load timers only once:
        let session_established = self.timers[TimeSessionEstablished];
        let handshake_started = self.timers[TimeLastHandshakeStarted];
        let data_packet_sent = self.timers[TimeLastDataPacketSent];

        {
            // Clear cookie after COOKIE_EXPIRATION_TIME
            if self.handshake.has_cookie()
                && now - self.timers[TimeCookieReceived] >= COOKIE_EXPIRATION_TIME
            {
                self.handshake.clear_cookie();
            }

            // All ephemeral private keys and symmetric session keys are zeroed out after
            // (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
            if now - session_established
                >= self.timers.reject_after_time.max(Duration::from_secs(
                    self.timers.range_max(2, REJECT_AFTER_TIME.as_secs() as u32) as u64,
                )) * 3
            {
                tracing::error!("CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
                self.handshake.set_expired();
                self.clear_all();
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            if let Some(time_init_sent) = self.handshake.timer() {
                // Handshake Initiation Retransmission
                let legacy_attempt_deadline = self
                    .timers
                    .timer_ranges
                    .iter()
                    .all(|range| *range == (0, 0))
                    && now - handshake_started >= REKEY_ATTEMPT_TIME;
                if legacy_attempt_deadline {
                    // Preserve BoringTun's legacy 90-second timeout when no AWG
                    // timer ranges are configured.
                    tracing::error!("CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
                    self.handshake.set_expired();
                    self.clear_all();
                    return TunnResult::Err(WireGuardError::ConnectionExpired);
                }

                if time_init_sent.elapsed()
                    >= self.timers.rekey_timeout + self.timers.handshake_retry_jitter
                {
                    // The upstream checks the retry budget when the retransmit
                    // timer expires, not on every polling tick.
                    if self.timers.handshake_attempts > self.timers.max_handshake_attempts {
                        tracing::warn!(
                            message = "HANDSHAKE(MAX_HANDSHAKE_ATTEMPTS)",
                            attempts = self.timers.handshake_attempts,
                            max_attempts = self.timers.max_handshake_attempts
                        );

                        // Match amneziawg-go's expiredRetransmitHandshake:
                        // stop this retry cycle and drop staged packets, but
                        // retain any still-valid session keypairs. They expire
                        // independently after RejectAfterTime * 3.
                        self.handshake.abort_initiation();
                        self.packet_queue.clear();
                        self.timers.send_keepalive_deadline = None;
                        self.timers.need_another_keepalive = false;
                        return TunnResult::Done;
                    }

                    // A handshake initiation is retried after the configured
                    // timeout plus 0..333 ms jitter.
                    tracing::warn!("HANDSHAKE(REKEY_TIMEOUT)");
                    self.timers.handshake_attempts =
                        self.timers.handshake_attempts.saturating_add(1);
                    self.timers.rekey_timeout = Duration::from_secs(
                        self.timers.pick_range(1, REKEY_TIMEOUT.as_secs() as u32) as u64,
                    );
                    self.timers.handshake_retry_jitter = Timers::random_jitter();
                    handshake_initiation_required = true;
                }
            } else {
                if self.timers.rekey_due_on_receive {
                    handshake_initiation_required = true;
                }

                if self.timers.is_initiator() {
                    // After sending a packet, if the sender was the original initiator
                    // of the handshake and if the current session key is REKEY_AFTER_TIME
                    // ms old, we initiate a new handshake. If the sender was the original
                    // responder of the handshake, it does not re-initiate a new handshake
                    // after REKEY_AFTER_TIME ms like the original initiator does.
                    if session_established < data_packet_sent
                        && now - session_established > self.timers.rekey_after_time
                    {
                        tracing::debug!("HANDSHAKE(REKEY_AFTER_TIME (on send))");
                        handshake_initiation_required = true;
                    }

                }

                // If we have sent a packet to a given peer but have not received a
                // packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms,
                // we initiate a new handshake.
                if self
                    .timers
                    .new_handshake_deadline
                    .map(|deadline| now >= deadline)
                    .unwrap_or(false)
                {
                    tracing::warn!("HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
                    self.timers.new_handshake_deadline = None;
                    handshake_initiation_required = true;
                }

                if !handshake_initiation_required {
                    // The first data receive starts this timer. If more data
                    // arrived while it was pending, upstream sends one extra
                    // keepalive after the first keepalive has gone out.
                    if self
                        .timers
                        .send_keepalive_deadline
                        .map(|deadline| now >= deadline)
                        .unwrap_or(false)
                    {
                        tracing::debug!("KEEPALIVE(KEEPALIVE_TIMEOUT)");
                        self.timers.send_keepalive_deadline = None;
                        if self.timers.need_another_keepalive {
                            self.timers.need_another_keepalive = false;
                            let timeout = self
                                .timers
                                .pick_range(3, KEEPALIVE_TIMEOUT.as_secs() as u32);
                            keepalive_rearm = Some(Duration::from_secs(timeout as u64));
                        }
                        keepalive_required = true;
                    }
                }
            }

            // Persistent keepalive is an independent timer in the Go device;
            // it remains active while a handshake retransmission is pending.
            if self
                .timers
                .persistent_keepalive_deadline
                .map(|deadline| now >= deadline)
                .unwrap_or(false)
            {
                tracing::debug!("KEEPALIVE(PERSISTENT_KEEPALIVE)");
                self.timers.persistent_keepalive_deadline = None;
                self.timer_tick(TimePersistentKeepalive);
                keepalive_required = true;
            }
        }

        if handshake_initiation_required {
            return self.format_handshake_initiation(dst, true);
        }

        if keepalive_required {
            let result = self.encapsulate(&[], dst);
            // encapsulate marks the keepalive as sent and clears the old
            // deadline. Re-arm only after a timer-driven send, matching
            // expiredSendKeepalive; a persistent keepalive must not re-arm it.
            if let Some(timeout) = keepalive_rearm {
                self.timers.send_keepalive_deadline =
                    Some(Instant::now().duration_since(self.timers.time_started) + timeout);
            }
            return result;
        }

        TunnResult::Done
    }

    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        let last_handshake = self.timers.last_handshake?;
        let duration_since_tun_start = Instant::now().duration_since(self.timers.time_started);
        Some(duration_since_tun_start.saturating_sub(last_handshake))
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        u16::try_from(self.timers.persistent_keepalive_interval)
            .ok()
            .filter(|interval| *interval > 0)
    }

    /// Return the configured inclusive persistent-keepalive interval range.
    pub fn persistent_keepalive_range(&self) -> Option<(u32, u32)> {
        let range = self.timers.persistent_keepalive_range;
        (range != (0, 0)).then_some(range)
    }
}

impl Timers {
    pub(super) fn set_timer_ranges(&mut self, amnezia: &AmneziaConfig) {
        self.timer_ranges = [
            amnezia.rekey_after_time,
            amnezia.rekey_timeout,
            amnezia.reject_after_time,
            amnezia.keepalive_timeout,
            amnezia.max_handshake_attempts,
        ];
    }

    /// Replace the persistent-keepalive interval range. A transition from
    /// disabled to enabled schedules an immediate keepalive, matching upstream's
    /// post-configuration pkaOn behavior. Later authenticated packet traversal
    /// samples a fresh interval from the configured range.
    pub(super) fn set_persistent_keepalive_range(&mut self, range: (u32, u32)) {
        let was_disabled = self.persistent_keepalive_range == (0, 0);
        self.persistent_keepalive_range = range;
        if range == (0, 0) {
            self.persistent_keepalive_interval = 0;
            self.persistent_keepalive_deadline = None;
        } else if was_disabled {
            let now = Instant::now().duration_since(self.time_started);
            self.persistent_keepalive_interval = self.pick_persistent_keepalive_interval();
            self.persistent_keepalive_deadline = Some(now);
        }
    }

    pub(super) fn set_persistent_keepalive(&mut self, keepalive: Option<u16>) {
        let interval = u32::from(keepalive.unwrap_or(0));
        self.set_persistent_keepalive_range((interval, interval));
    }
}
