#![deny(clippy::disallowed_types)]
#![allow(warnings)]

use std::sync::LazyLock;
use log::info;
use crate::logger::hytale_logger;
use crate::logger::hytale_logger::AsyncLogger;
use crate::server::core::hytale_server::{HytaleServer, HYTALE_SERVER};
use crate::server::core::options;
use crate::utils::scheduler::scheduler::Scheduler;

mod logger;
mod server;
mod event;
mod utils;
mod plugin;
mod protocol;

#[tokio::main]
async fn main() {
    options::parse();
    AsyncLogger::init();
    HYTALE_SERVER.init().await;

    HYTALE_SERVER.start().await;
    info!("Server Stopped")
}
