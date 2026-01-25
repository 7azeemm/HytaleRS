use crossbeam_channel::{unbounded, Receiver, Sender};
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use chrono::Local;
use colored::Colorize;
use log::{Log, Metadata, Record};

pub struct AsyncLogger {
    sender: Sender<LogMessage>,
}

struct LogMessage {
    level: String,
    message: String,
    timestamp: String,
    target: String,
}

impl AsyncLogger {
    pub fn init() -> Result<(), Box<dyn std::error::Error>> {
        let (tx, rx) = unbounded();

        // Spawn logger thread
        thread::spawn(move || {
            Self::logger_thread(rx, "./logs");
        });

        // Set global logger
        log::set_boxed_logger(Box::new(AsyncLogger { sender: tx }))?;
        log::set_max_level(log::LevelFilter::Info);

        Ok(())
    }

    fn logger_thread(rx: Receiver<LogMessage>, log_dir: &str) {
        // Open log file once
        let log_path = format!(
            "{}/{}_{}_server.log",
            log_dir,
            Local::now().format("%Y-%m-%d"),
            Local::now().format("%H-%M-%S")
        );

        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to open log file: {}", e);
                return;
            }
        };

        // Process messages
        while let Ok(msg) = rx.recv() {
            // Write to file
            let file_line = format!(
                "[{}] [{}] [{}] {}\n",
                msg.timestamp, msg.level, msg.target, msg.message
            );
            let _ = file.write_all(file_line.as_bytes());

            // Also write to stdout with colors (non-blocking)
            let level_colored = match msg.level.as_str() {
                "ERROR" => msg.level.red().bold().to_string(),
                "WARN" => msg.level.yellow().bold().to_string(),
                "INFO" => msg.level.green().bold().to_string(),
                "DEBUG" => msg.level.blue().bold().to_string(),
                "TRACE" => msg.level.purple().bold().to_string(),
                _ => msg.level.normal().to_string(),
            };

            println!("[{}] [{}] [{}] {}", msg.timestamp, level_colored, msg.target, msg.message);
        }

        let _ = file.flush();
    }
}

impl Log for AsyncLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let msg = LogMessage {
            level: record.level().to_string(),
            message: record.args().to_string(),
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            target: record
                .target()
                .split("::")
                .last()
                .unwrap_or(record.target())
                .to_string(),
        };

        let _ = self.sender.try_send(msg);
    }

    fn flush(&self) {}
}