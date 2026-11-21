//! The offline queue (LLD 2, section 6): events wait here while Helios is disconnected, and the
//! oldest is dropped when it's full. Nothing is written to disk.

use std::collections::VecDeque;

/// A bounded first-in, first-out queue that drops its oldest entry when full, and counts what it
/// dropped.
#[derive(Debug)]
pub(crate) struct OfflineQueue<T> {
    entries: VecDeque<T>,
    capacity: usize,
    dropped: u64,
}

impl<T> OfflineQueue<T> {
    /// An empty queue for at most `capacity` messages (at least one).
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity: capacity.max(1),
            dropped: 0,
        }
    }

    /// Adds `message`, dropping the oldest entry if the queue is full.
    pub(crate) fn push(&mut self, message: T) {
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
            self.dropped += 1;
        }
        self.entries.push_back(message);
    }

    /// Puts `message` back at the front, for one that couldn't be sent after all. If the queue
    /// filled up meanwhile, the newest entry is the one dropped.
    pub(crate) fn push_front(&mut self, message: T) {
        if self.entries.len() == self.capacity {
            self.entries.pop_back();
            self.dropped += 1;
        }
        self.entries.push_front(message);
    }

    /// The oldest message, if any.
    pub(crate) fn pop(&mut self) -> Option<T> {
        self.entries.pop_front()
    }

    /// How many messages are waiting.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is waiting.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many messages were dropped since the queue was made.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(n: u8) -> String {
        format!("t/{n}")
    }

    #[test]
    fn keeps_order_and_drops_the_oldest_when_full() {
        let mut queue = OfflineQueue::new(2);
        assert!(queue.is_empty());

        queue.push(message(1));
        queue.push(message(2));
        queue.push(message(3));

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped(), 1);
        assert_eq!(queue.pop(), Some(message(2)));
        assert_eq!(queue.pop(), Some(message(3)));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn puts_unsent_messages_back_at_the_front() {
        let mut queue = OfflineQueue::new(2);
        queue.push(message(2));
        queue.push(message(3));

        queue.push_front(message(1));

        assert_eq!(queue.dropped(), 1);
        assert_eq!(queue.pop(), Some(message(1)));
        assert_eq!(queue.pop(), Some(message(2)));
    }

    #[test]
    fn holds_at_least_one() {
        let mut queue = OfflineQueue::new(0);
        queue.push(message(1));

        assert_eq!(queue.len(), 1);
    }
}
