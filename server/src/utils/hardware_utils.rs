use std::process::Command;
use std::fs;
use uuid::Uuid;
use regex::Regex;
use once_cell::sync::Lazy;

static UUID_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
        .unwrap()
});

pub fn get_system_uuid() -> Uuid {
    match std::env::consts::OS {
        "windows" => get_uuid_windows(),
        "macos" => get_uuid_macos(),
        "linux" => get_uuid_linux(),
        _ => panic!("Unknown OS!")
    }
}

fn get_uuid_windows() -> Uuid {
    // Try registry
    if let Some(output) = run_command(&["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"]) {
        if let Some(uuid) = parse_uuid_from_output(&output) {
            return uuid;
        }
    }

    // Try PowerShell
    if let Some(output) = run_command(&["powershell", "-NoProfile", "-Command", "(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID"]) {
        if let Some(uuid) = parse_uuid_from_output(&output) {
            return uuid;
        }
    }

    // Try WMI
    if let Some(output) = run_command(&["wmic", "csproduct", "get", "UUID"]) {
        if let Some(uuid) = parse_uuid_from_output(&output) {
            return uuid;
        }
    }

    panic!("Failed to get hardware UUID for Windows");
}

fn get_uuid_macos() -> Uuid {
    // Try ioreg
    if let Some(output) = run_command(&["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]) {
        if let Some(uuid) = parse_uuid_from_output(&output) {
            return uuid;
        }
    }

    // Try system_profiler
    if let Some(output) = run_command(&["/usr/sbin/system_profiler", "SPHardwareDataType"]) {
        if let Some(uuid) = parse_uuid_from_output(&output) {
            return uuid;
        }
    }

    panic!("Failed to get hardware UUID for macOS");
}

fn get_uuid_linux() -> Uuid {
    // Try /etc/machine-id
    if let Some(uuid) = read_machine_id_file("/etc/machine-id") {
        return uuid;
    }

    // Try /var/lib/dbus/machine-id
    if let Some(uuid) = read_machine_id_file("/var/lib/dbus/machine-id") {
        return uuid;
    }

    // Try /sys/class/dmi/id/product_uuid
    if let Ok(content) = fs::read_to_string("/sys/class/dmi/id/product_uuid") {
        if let Ok(uuid) = Uuid::parse_str(content.trim()) {
            return uuid;
        }
    }

    // Try dmidecode
    if let Some(output) = run_command(&["dmidecode", "-s", "system-uuid"]) {
        if let Some(uuid) = parse_uuid_from_output(&output) {
            return uuid;
        }
    }

    panic!("Failed to get hardware UUID for Linux");
}

fn run_command(cmd: &[&str]) -> Option<String> {
    if cmd.is_empty() {
        return None;
    }

    let mut command = Command::new(cmd[0]);
    for arg in &cmd[1..] {
        command.arg(arg);
    }

    match command.output() {
        Ok(output) if output.status.success() => {
            String::from_utf8(output.stdout).ok().map(|s| s.trim().to_string())
        }
        _ => None,
    }
}

fn parse_uuid_from_output(output: &str) -> Option<Uuid> {
    UUID_PATTERN
        .find(output)
        .and_then(|m| Uuid::parse_str(m.as_str()).ok())
}

fn read_machine_id_file(path: &str) -> Option<Uuid> {
    let content = fs::read_to_string(path).ok()?.trim().to_string();

    if content.is_empty() || content.len() != 32 {
        return None;
    }

    let uuid_str = format!(
        "{}-{}-{}-{}-{}",
        &content[0..8],
        &content[8..12],
        &content[12..16],
        &content[16..20],
        &content[20..32]
    );

    Uuid::parse_str(&uuid_str).ok()
}