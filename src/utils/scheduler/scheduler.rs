use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use ahash::{HashMap, HashMapExt};
use crossbeam::channel::{Receiver, Sender};
use crossbeam_channel::TrySendError;

pub type JobId = u64;
type JobFn = Box<dyn FnMut() + Send + 'static>;

pub struct Job {
    id: JobId,
    next_run: Instant,
    interval: Option<Duration>,
    task: JobFn,
}

pub enum SchedulerCmd {
    Schedule(Job),
    Cancel(JobId),
}

#[derive(Clone)]
pub struct Scheduler {
    tx: Sender<SchedulerCmd>,
    next_id: Arc<AtomicU64>,
}

impl Scheduler {
    pub fn new() -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();

        let scheduler = Scheduler {
            tx: tx.clone(),
            next_id: Arc::new(AtomicU64::new(1)),
        };

        thread::Builder::new()
            .name("background-scheduler".into())
            .spawn(move || run_scheduler(rx))
            .expect("Failed to start scheduler");

        scheduler
    }

    pub fn schedule_once<F>(&self, delay: Duration, task: F) -> Result<JobId, TrySendError<SchedulerCmd>>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut opt = Some(task);
        self.schedule_interval(delay, None, move || {
            if let Some(f) = opt.take() {
                f();
            }
        })
    }

    pub fn schedule_interval<F>(
        &self,
        delay: Duration,
        interval: Option<Duration>,
        task: F,
    ) -> Result<JobId, TrySendError<SchedulerCmd>>
    where
        F: FnMut() + Send + 'static,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let job = Job {
            id,
            next_run: Instant::now() + delay,
            interval,
            task: Box::new(task),
        };

        self.tx.try_send(SchedulerCmd::Schedule(job))?;
        Ok(id)
    }

    pub fn cancel(&self, id: JobId) {
        let _ = self.tx.try_send(SchedulerCmd::Cancel(id));
    }
}

fn run_scheduler(rx: Receiver<SchedulerCmd>) {
    let mut heap = BinaryHeap::<Reverse<(Instant, JobId)>>::new();
    let mut jobs = HashMap::<JobId, Job>::new();

    loop {
        // Process incoming commands
        process_commands(&rx, &mut heap, &mut jobs);

        // Execute jobs
        execute_jobs(&mut heap, &mut jobs);

        // Wait for commands or jobs
        wait_for_next(&heap);
    }
}

#[inline]
fn process_commands(
    rx: &Receiver<SchedulerCmd>,
    heap: &mut BinaryHeap<Reverse<(Instant, JobId)>>,
    jobs: &mut HashMap<JobId, Job>,
) {
    const MAX_BATCH_SIZE: usize = 1000;

    for _ in 0..MAX_BATCH_SIZE {
        match rx.try_recv() {
            Ok(SchedulerCmd::Schedule(job)) => {
                heap.push(Reverse((job.next_run, job.id)));
                jobs.insert(job.id, job);
            }
            Ok(SchedulerCmd::Cancel(id)) => {
                jobs.remove(&id);
            }
            Err(_) => break,
        }
    }
}

#[inline]
fn execute_jobs(
    heap: &mut BinaryHeap<Reverse<(Instant, JobId)>>,
    jobs: &mut HashMap<JobId, Job>,
) {
    const MAX_JOBS_PER_CYCLE: usize = 1000;

    for _ in 0..MAX_JOBS_PER_CYCLE {
        let should_pop = heap.peek()
            .map(|Reverse((time, _))| Instant::now() >= *time)
            .unwrap_or(false);

        if !should_pop {
            break;
        }

        if let Some(Reverse((_, id))) = heap.pop() {
            if let Some(job) = jobs.get_mut(&id) {
                (job.task)();

                if let Some(interval) = job.interval {
                    //TODO: warning if task took too long?
                    job.next_run += interval;
                    heap.push(Reverse((job.next_run, id)));
                } else {
                    jobs.remove(&id);
                }
            }
        }
    }
}

#[inline]
fn wait_for_next(heap: &BinaryHeap<Reverse<(Instant, JobId)>>) {
    if let Some(Reverse((next_time, _))) = heap.peek() {
        let now = Instant::now();
        if *next_time > now {
            thread::sleep((*next_time - now).min(Duration::from_millis(100)));
        }
    } else {
        thread::sleep(Duration::from_millis(1));
    }
}