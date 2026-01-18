use std::fmt::Write;
use serde::{Deserialize, Deserializer, Serializer};
use std::time::Duration;

pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = format_iso8601_duration(duration);
    serializer.serialize_str(&s)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = <&str>::deserialize(deserializer)?;
    parse_iso8601_duration(s).map_err(serde::de::Error::custom)
}

pub mod map {
    use ahash::HashMap;
    use serde::ser::SerializeMap;
    use super::*;

    pub fn serialize<S>(map: &HashMap<String, Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            m.serialize_entry(k, &format_iso8601_duration(v))?;
        }
        m.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<String, Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = HashMap::<String, String>::deserialize(deserializer)?;
        raw.into_iter()
            .map(|(k, v)| {
                parse_iso8601_duration(&v)
                    .map(|d| (k, d))
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

#[inline]
fn parse_iso8601_duration(input: &str) -> Result<Duration, String> {
    let bytes = input.as_bytes();

    if bytes.first() != Some(&b'P') {
        return Err("Duration must start with 'P'".into());
    }

    let mut secs: u64 = 0;
    let mut nanos: u32 = 0;
    let mut num_start = 1;
    let mut in_time = false;
    let mut i = 1;

    while i < bytes.len() {
        let c = bytes[i];

        match c {
            b'T' => {
                in_time = true;
                num_start = i + 1;
            }
            b'0'..=b'9' | b'.' => {}
            b'D' => {
                secs += parse_u64_bytes(&bytes[num_start..i])? * 86_400;
                num_start = i + 1;
            }
            b'H' if in_time => {
                secs += parse_u64_bytes(&bytes[num_start..i])? * 3_600;
                num_start = i + 1;
            }
            b'M' if in_time => {
                secs += parse_u64_bytes(&bytes[num_start..i])? * 60;
                num_start = i + 1;
            }
            b'S' if in_time => {
                let (s, ns) = parse_seconds_bytes(&bytes[num_start..i])?;
                secs += s;
                nanos += ns;
                num_start = i + 1;
            }
            _ => return Err(format!("Invalid character '{}'", c as char)),
        }
        i += 1;
    }

    Ok(Duration::new(secs, nanos))
}

#[inline]
fn format_iso8601_duration(duration: &Duration) -> String {
    if duration.is_zero() { return "PT0S".into(); }

    let mut secs = duration.as_secs();
    let nanos = duration.subsec_nanos();

    let days = secs / 86_400;
    secs %= 86_400;
    let hours = secs / 3_600;
    secs %= 3_600;
    let minutes = secs / 60;
    secs %= 60;

    let mut out = String::with_capacity(20);
    out.push('P');

    if days > 0 {
        let _ = write!(out, "{}D", days);
    }

    if hours > 0 || minutes > 0 || secs > 0 || nanos > 0 {
        out.push('T');
        if hours > 0 {
            let _ = write!(out, "{}H", hours);
        }
        if minutes > 0 {
            let _ = write!(out, "{}M", minutes);
        }
        if nanos == 0 {
            if secs > 0 {
                let _ = write!(out, "{}S", secs);
            }
        } else {
            // Trim trailing zeros from nanoseconds
            let mut n = nanos;
            let mut width = 9;
            while n % 10 == 0 && width > 1 {
                n /= 10;
                width -= 1;
            }
            let _ = write!(out, "{}.{:0width$}S", secs, n, width = width);
        }
    }
    out
}

#[inline]
fn parse_u64_bytes(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() {
        return Err("Empty number".into());
    }

    let mut result = 0u64;
    for &b in bytes {
        if !(b'0'..=b'9').contains(&b) {
            return Err(format!("Invalid digit: {}", b as char));
        }
        result = result.checked_mul(10)
            .and_then(|r| r.checked_add((b - b'0') as u64))
            .ok_or_else(|| "Number overflow".to_string())?;
    }
    Ok(result)
}

#[inline]
fn parse_seconds_bytes(bytes: &[u8]) -> Result<(u64, u32), String> {
    if let Some(dot_pos) = bytes.iter().position(|&b| b == b'.') {
        let secs = parse_u64_bytes(&bytes[..dot_pos])?;
        let frac = &bytes[dot_pos + 1..];

        let mut nanos: u32 = 0;
        let digits = frac.len().min(9);

        for &b in frac.iter().take(9) {
            if !(b'0'..=b'9').contains(&b) {
                return Err("Invalid fraction".into());
            }
            nanos = nanos * 10 + (b - b'0') as u32;
        }

        if digits < 9 {
            nanos *= 10u32.pow((9 - digits) as u32);
        }

        Ok((secs, nanos))
    } else {
        Ok((parse_u64_bytes(bytes)?, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(parse_iso8601_duration("PT1H").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_iso8601_duration("P1D").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_iso8601_duration("PT1.5S").unwrap(), Duration::new(1, 500_000_000));
    }

    #[test]
    fn test_format() {
        assert_eq!(format_iso8601_duration(&Duration::from_secs(3600)), "PT1H");
        assert_eq!(format_iso8601_duration(&Duration::new(1, 500_000_000)), "PT1.5S");
        assert_eq!(format_iso8601_duration(&Duration::new(0, 123_456_789)), "PT0.123456789S");
    }
}