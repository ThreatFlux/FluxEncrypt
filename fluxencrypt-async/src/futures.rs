//! Future-based utilities and async helpers.

use fluxencrypt::error::{FluxError, Result};
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
    /// A future that wraps a CPU-intensive encryption operation
    pub struct EncryptionFuture<F> {
        #[pin]
        future: F,
    }
}

impl<F> EncryptionFuture<F>
where
    F: Future<Output = Result<Vec<u8>>>,
{
    /// Create a new encryption future
    pub fn new(future: F) -> Self {
        Self { future }
    }
}

impl<F> Future for EncryptionFuture<F>
where
    F: Future<Output = Result<Vec<u8>>>,
{
    type Output = Result<Vec<u8>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        this.future.poll(cx)
    }
}

pin_project! {
    /// A future that wraps a CPU-intensive decryption operation
    pub struct DecryptionFuture<F> {
        #[pin]
        future: F,
    }
}

impl<F> DecryptionFuture<F>
where
    F: Future<Output = Result<Vec<u8>>>,
{
    /// Create a new decryption future
    pub fn new(future: F) -> Self {
        Self { future }
    }
}

impl<F> Future for DecryptionFuture<F>
where
    F: Future<Output = Result<Vec<u8>>>,
{
    type Output = Result<Vec<u8>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        this.future.poll(cx)
    }
}

/// Create a future that yields control to allow other tasks to run
pub async fn yield_now() {
    tokio::task::yield_now().await;
}

/// Run a blocking operation on a thread pool and return a future
pub async fn spawn_blocking_encryption<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| FluxError::other(e.into()))?
}

/// A utility for batching async operations
pub struct AsyncBatch<T> {
    items: Vec<T>,
    batch_size: usize,
}

impl<T> AsyncBatch<T> {
    /// Create a new async batch processor
    pub fn new(items: Vec<T>, batch_size: usize) -> Self {
        Self { items, batch_size }
    }

    /// Process items in batches with a given async function
    pub async fn process_with<F, Fut, R, E>(&self, f: F) -> Vec<std::result::Result<R, E>>
    where
        F: Fn(&T) -> Fut + Clone,
        Fut: Future<Output = std::result::Result<R, E>>,
        R: Send + 'static,
        E: Send + 'static,
    {
        use futures::stream::{FuturesUnordered, StreamExt};

        let mut results = Vec::new();
        let mut current_batch = FuturesUnordered::new();

        for item in &self.items {
            current_batch.push(f(item));

            if current_batch.len() >= self.batch_size {
                while let Some(result) = current_batch.next().await {
                    results.push(result);
                }
            }
        }

        // Process remaining items
        while let Some(result) = current_batch.next().await {
            results.push(result);
        }

        results
    }
}

/// A progress tracker for async operations
pub struct AsyncProgressTracker {
    total: u64,
    current: u64,
    callback: Option<Box<dyn Fn(u64, u64) + Send + Sync>>,
}

impl AsyncProgressTracker {
    /// Create a new progress tracker
    pub fn new(total: u64) -> Self {
        Self {
            total,
            current: 0,
            callback: None,
        }
    }

    /// Set a progress callback
    pub fn with_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(u64, u64) + Send + Sync + 'static,
    {
        self.callback = Some(Box::new(callback));
        self
    }

    /// Update progress and call callback if set
    pub async fn update(&mut self, progress: u64) {
        self.current = progress.min(self.total);

        if let Some(ref callback) = self.callback {
            callback(self.current, self.total);
        }

        // Yield to allow other tasks to run
        yield_now().await;
    }

    /// Mark as completed
    pub async fn complete(&mut self) {
        self.update(self.total).await;
    }

    /// Get current progress percentage
    pub fn percentage(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.current as f64 / self.total as f64) * 100.0
        }
    }
}

/// Create a timeout future for async operations
pub async fn with_timeout<F>(
    future: F,
    duration: std::time::Duration,
) -> std::result::Result<F::Output, tokio::time::error::Elapsed>
where
    F: Future,
{
    tokio::time::timeout(duration, future).await
}

/// Retry an async operation with exponential backoff
pub async fn retry_with_backoff<F, Fut, T, E>(
    mut operation: F,
    max_retries: usize,
    initial_delay: std::time::Duration,
) -> std::result::Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut attempts = 0;
    let mut delay = initial_delay;

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                attempts += 1;
                if attempts > max_retries {
                    return Err(error);
                }

                log::debug!(
                    "Operation failed (attempt {}/{}), retrying in {:?}: {:?}",
                    attempts,
                    max_retries,
                    delay,
                    error
                );

                tokio::time::sleep(delay).await;
                delay *= 2; // Exponential backoff
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_async_batch() {
        let items = vec![1, 2, 3, 4, 5];
        let batch = AsyncBatch::new(items, 2);

        let results = batch
            .process_with(|&x| async move {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                Ok::<i32, ()>(x * 2)
            })
            .await;

        assert_eq!(results.len(), 5);
        for (i, result) in results.iter().enumerate() {
            assert_eq!(*result, Ok((i as i32 + 1) * 2));
        }
    }

    #[tokio::test]
    async fn test_progress_tracker() {
        let callback_counter = Arc::new(AtomicU64::new(0));
        let counter_clone = callback_counter.clone();

        let mut tracker = AsyncProgressTracker::new(100).with_callback(move |current, total| {
            counter_clone.fetch_add(1, Ordering::Relaxed);
            assert!(current <= total);
        });

        tracker.update(50).await;
        assert_eq!(tracker.percentage(), 50.0);

        tracker.complete().await;
        assert_eq!(tracker.percentage(), 100.0);

        // Verify callback was called
        assert!(callback_counter.load(Ordering::Relaxed) >= 2);
    }

    #[tokio::test]
    async fn test_with_timeout() {
        // Test successful operation within timeout
        let result = with_timeout(
            async {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                42
            },
            std::time::Duration::from_millis(100),
        )
        .await;
        assert_eq!(result.unwrap(), 42);

        // Test timeout
        let result = with_timeout(
            async {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                42
            },
            std::time::Duration::from_millis(50),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_retry_with_backoff() {
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = counter.clone();

        let result = retry_with_backoff(
            move || {
                let counter = counter_clone.clone();
                async move {
                    let count = counter.fetch_add(1, Ordering::Relaxed);
                    if count < 2 {
                        Err("not ready")
                    } else {
                        Ok(42)
                    }
                }
            },
            5,
            std::time::Duration::from_millis(1),
        )
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }
}
