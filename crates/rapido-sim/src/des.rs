//! Discrete-event simulation core.
//!
//! Virtual time only — no wall-clock sleeping — so a run is a pure function of
//! its seed and completes in whatever time the host takes. Ties in the event
//! queue break on a monotonic sequence number, which is what makes runs
//! bit-for-bit reproducible rather than merely statistically similar.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// An event scheduled at a virtual time.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Scheduled<E> {
    time_ns: u64,
    seq: u64,
    event: E,
}

impl<E: Eq> Ord for Scheduled<E> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Ordering is by (time, seq) only; `event` never participates, so two
        // events at the same instant always resolve in insertion order.
        self.time_ns.cmp(&other.time_ns).then(self.seq.cmp(&other.seq))
    }
}

impl<E: Eq> PartialOrd for Scheduled<E> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A virtual-time event queue.
#[derive(Debug)]
pub struct EventQueue<E: Eq> {
    heap: BinaryHeap<Reverse<Scheduled<E>>>,
    next_seq: u64,
    now_ns: u64,
}

impl<E: Eq> Default for EventQueue<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Eq> EventQueue<E> {
    pub fn new() -> Self {
        EventQueue { heap: BinaryHeap::new(), next_seq: 0, now_ns: 0 }
    }

    pub fn now_ns(&self) -> u64 {
        self.now_ns
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Schedule at an absolute virtual time. Scheduling into the past is a bug
    /// in the caller, not something to silently reorder.
    pub fn schedule_at(&mut self, time_ns: u64, event: E) {
        debug_assert!(
            time_ns >= self.now_ns,
            "event scheduled at {time_ns} is before the current time {}",
            self.now_ns
        );
        self.heap.push(Reverse(Scheduled { time_ns, seq: self.next_seq, event }));
        self.next_seq += 1;
    }

    pub fn schedule_after(&mut self, delay_ns: u64, event: E) {
        self.schedule_at(self.now_ns + delay_ns, event);
    }

    /// Pop the next event and advance the clock to it.
    //
    // Named `next` deliberately: this is the queue's pop-and-advance step, not
    // an `Iterator` (the queue is mutated by handlers while draining, which an
    // `Iterator` impl could not express).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(u64, E)> {
        let Reverse(s) = self.heap.pop()?;
        self.now_ns = s.time_ns;
        Some((s.time_ns, s.event))
    }
}

/// A bounded pool of verifier workers with a FIFO admission queue.
///
/// Models an RSU with `n_cores` verification threads. Requests that arrive
/// while every core is busy wait in the queue; the maximum queue depth reached
/// is one of the numbers Scenario 1 reports.
#[derive(Debug)]
pub struct ServerPool {
    pub n_cores: usize,
    busy: usize,
    queue: std::collections::VecDeque<u64>,
    max_depth: usize,
    total_admitted: u64,
    busy_ns: u64,
}

impl ServerPool {
    pub fn new(n_cores: usize) -> Self {
        assert!(n_cores > 0, "a verifier needs at least one core");
        ServerPool {
            n_cores,
            busy: 0,
            queue: std::collections::VecDeque::new(),
            max_depth: 0,
            total_admitted: 0,
            busy_ns: 0,
        }
    }

    /// Offer a request at `now_ns`. Returns `Some(queue_wait_ns)` if a core was
    /// free (wait is zero), or `None` if it was queued.
    pub fn offer(&mut self, now_ns: u64) -> Option<u64> {
        if self.busy < self.n_cores {
            self.busy += 1;
            self.total_admitted += 1;
            Some(0)
        } else {
            self.queue.push_back(now_ns);
            self.max_depth = self.max_depth.max(self.queue.len());
            None
        }
    }

    /// A core finished. Returns the arrival time of the next queued request, if
    /// any, so the caller can compute its wait and schedule its completion.
    pub fn complete(&mut self, service_ns: u64) -> Option<u64> {
        debug_assert!(self.busy > 0, "completion with no busy core");
        self.busy -= 1;
        self.busy_ns += service_ns;
        if let Some(arrived) = self.queue.pop_front() {
            self.busy += 1;
            self.total_admitted += 1;
            Some(arrived)
        } else {
            None
        }
    }

    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }
    pub fn max_queue_depth(&self) -> usize {
        self.max_depth
    }
    pub fn busy_cores(&self) -> usize {
        self.busy
    }
    pub fn total_admitted(&self) -> u64 {
        self.total_admitted
    }

    /// Fraction of total core-time spent serving, over a window.
    pub fn utilization(&self, window_ns: u64) -> f64 {
        if window_ns == 0 {
            return 0.0;
        }
        self.busy_ns as f64 / (window_ns as f64 * self.n_cores as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    enum E {
        A(u32),
    }

    #[test]
    fn events_come_out_in_time_order() {
        let mut q = EventQueue::new();
        q.schedule_at(30, E::A(3));
        q.schedule_at(10, E::A(1));
        q.schedule_at(20, E::A(2));
        let seen: Vec<_> = std::iter::from_fn(|| q.next()).collect();
        assert_eq!(seen, vec![(10, E::A(1)), (20, E::A(2)), (30, E::A(3))]);
    }

    #[test]
    fn ties_break_in_insertion_order() {
        let mut q = EventQueue::new();
        for i in 0..10u32 {
            q.schedule_at(100, E::A(i));
        }
        let seen: Vec<u32> = std::iter::from_fn(|| q.next()).map(|(_, E::A(i))| i).collect();
        assert_eq!(seen, (0..10).collect::<Vec<_>>(), "tie-breaking must be deterministic");
    }

    #[test]
    fn clock_advances_with_events() {
        let mut q = EventQueue::new();
        assert_eq!(q.now_ns(), 0);
        q.schedule_at(500, E::A(1));
        q.next();
        assert_eq!(q.now_ns(), 500);
        q.schedule_after(250, E::A(2));
        q.next();
        assert_eq!(q.now_ns(), 750);
    }

    #[test]
    fn single_core_pool_serializes_requests() {
        let mut p = ServerPool::new(1);
        assert_eq!(p.offer(0), Some(0));
        assert_eq!(p.offer(10), None);
        assert_eq!(p.offer(20), None);
        assert_eq!(p.queue_depth(), 2);
        assert_eq!(p.complete(100), Some(10));
        assert_eq!(p.complete(100), Some(20));
        assert_eq!(p.complete(100), None);
        assert_eq!(p.max_queue_depth(), 2);
    }

    #[test]
    fn multicore_pool_admits_up_to_n_concurrently() {
        let mut p = ServerPool::new(4);
        for i in 0..4 {
            assert_eq!(p.offer(i), Some(0), "core {i} should have been free");
        }
        assert_eq!(p.busy_cores(), 4);
        assert_eq!(p.offer(5), None);
        assert_eq!(p.queue_depth(), 1);
    }

    #[test]
    fn utilization_is_busy_time_over_core_time() {
        let mut p = ServerPool::new(2);
        p.offer(0);
        p.complete(500);
        // 500 ns of work over 1000 ns on 2 cores = 25%.
        assert!((p.utilization(1000) - 0.25).abs() < 1e-9);
    }

    #[test]
    fn total_admitted_counts_every_served_request() {
        let mut p = ServerPool::new(2);
        for i in 0..6u64 {
            p.offer(i);
        }
        // 2 admitted immediately, 4 queued.
        while p.busy_cores() > 0 {
            if p.complete(10).is_none() && p.queue_depth() == 0 {
                break;
            }
        }
        assert_eq!(p.total_admitted(), 6);
    }
}
