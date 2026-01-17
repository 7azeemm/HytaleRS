use crate::logger::hytale_logger;

mod logger;

fn main() {
    hytale_logger::init().expect("Failed to setup logger");
}
