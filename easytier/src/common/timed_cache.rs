use std::time::{Duration, Instant};

pub struct Timed<T> {
    update_time: Instant,
    value: T,
}
impl<T> Timed<T> {
    pub fn new(value: T) -> Self {
        Self {
            update_time: Instant::now(),
            value,
        }
    }
    pub fn is_expired(&self, duration: Duration) -> bool {
        self.update_time.elapsed() > duration
    }
    pub fn get(&self) -> &T {
        &self.value
    }
}
