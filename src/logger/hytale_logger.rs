use std::error::Error;
use std::fs;
use std::path::Path;
use chrono::Local;
use colored::Colorize;
use fern::Dispatch;
use log::{info, LevelFilter};

pub fn init() -> Result<(), Box<dyn Error>> {
    let file_path = log_file_path()?;

    let console_dispatch = Dispatch::new()
        .format(|out, message, record| {
            let level = match record.level() {
                log::Level::Error => "ERROR".red().bold(),
                log::Level::Warn  => "WARN".yellow().bold(),
                log::Level::Info  => "INFO".green().bold(),
                log::Level::Debug => "DEBUG".blue().bold(),
                log::Level::Trace => "TRACE".purple().bold(),
            };

            let time = Local::now().format("%Y-%m-%d %H:%M:%S");
            let module = record.target().split("::").last().unwrap_or(record.target());
            out.finish(format_args!("[{}] [{}] [{}] {}", time, level, module, message))
        })
        .chain(std::io::stdout());

    let file_dispatch = Dispatch::new()
        .format(|out, message, record| {
            let time = Local::now().format("%Y-%m-%d %H:%M:%S");
            let module = record.target().split("::").last().unwrap_or(record.target());
            out.finish(format_args!("[{}] [{}] [{}] {}", time, record.level(), module, message))
        })
        .chain(fern::log_file(file_path)?);

    Dispatch::new()
        .level(LevelFilter::Info)
        .chain(console_dispatch)
        .chain(file_dispatch)
        .apply()?;

    info!("Logger Initialized");

    Ok(())
}

fn log_file_path() -> std::io::Result<String> {
    let logs_dir = Path::new("logs");
    if !logs_dir.exists() {
        fs::create_dir_all(logs_dir)?;
    }

    let now = Local::now();
    let filename = format!(
        "{}_{}_server.log",
        now.format("%Y-%m-%d"),
        now.format("%H-%M-%S")
    );

    Ok(logs_dir.join(filename).to_string_lossy().to_string())
}