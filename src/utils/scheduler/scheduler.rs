use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use ahash::{HashMap, HashMapExt};
use tokio::sync::RwLock;
use tokio::time::sleep;

pub static GLOBAL_SCHEDULER: LazyLock<Scheduler> = LazyLock::new(|| Scheduler::new());

pub type JobId = u64;
pub type AsyncTask = Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync + 'static>;

#[derive(Clone)]
pub struct Scheduler {
    jobs: Arc<RwLock<HashMap<JobId, bool>>>,
    next_id: Arc<AtomicU64>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Schedule an async task to run repeatedly at intervals
    pub fn schedule_interval<F>(&self, delay: Duration, interval: Duration, task: F) -> JobId
    where
        F: Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync + 'static,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        self.jobs.blocking_write().insert(id, true);
        let jobs = self.jobs.clone();

        tokio::spawn(async move {
            sleep(delay).await;

            let mut timer = tokio::time::interval(interval);
            loop {
                // Check if job was canceled
                if !jobs.read().await.contains_key(&id) {
                    break;
                }

                // Execute the async task
                task().await;

                // Wait
                timer.tick().await;
            }
        });

        id
    }

    /// Cancel a scheduled job
    pub async fn cancel(&self, id: JobId) {
        self.jobs.write().await.remove(&id);
    }
}
