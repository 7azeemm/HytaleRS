#![deny(clippy::disallowed_types)]
#![allow(warnings)]

use std::sync::LazyLock;
use log::info;
use crate::logger::hytale_logger;
use crate::server::core::hytale_server::{HytaleServer, HYTALE_SERVER};
use crate::server::core::options;
use crate::util::scheduler::scheduler::Scheduler;

mod logger;
mod server;
mod event;
mod util;
mod plugin;
mod protocol;

pub static GLOBAL_SCHEDULER: LazyLock<Scheduler> = LazyLock::new(|| Scheduler::new());

#[tokio::main]
async fn main() {
    options::parse();
    hytale_logger::init().expect("Failed to setup logger");
    HYTALE_SERVER.init();

    HYTALE_SERVER.start().await;
    info!("Server Stopped")
}
