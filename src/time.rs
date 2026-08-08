//! UTC timestamps without a date-time dependency.
//!
//! The audit log needs one field a human can read. Pulling in a calendar crate
//! for that would be the largest dependency in the tool, so the civil-date
//! conversion is inlined here: it is forty lines of well-specified arithmetic
//! with exact test vectors, which is a smaller thing to own than a dependency.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch.
///
/// A clock set before 1970 yields 0 rather than an error: a wrong timestamp in
/// an audit row is a lesser problem than a command that refuses to run.
#[must_use]
pub fn now_unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Render epoch milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
#[must_use]
pub fn rfc3339_utc(millis: u128) -> String {
    let total_secs = (millis / 1000) as i64;
    let millis_part = (millis % 1000) as u32;

    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis_part:03}Z")
}

/// Days since the Unix epoch to a proleptic Gregorian date.
///
/// Howard Hinnant's `civil_from_days`, which shifts the epoch to 0000-03-01 so
/// the leap day lands at the end of a 400-year era and the whole conversion
/// becomes integer division with no branches on month length.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March-based
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::rfc3339_utc;

    #[test]
    fn the_epoch_renders_exactly() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn known_instants_render_exactly() {
        assert_eq!(rfc3339_utc(1_000_000_000_000), "2001-09-09T01:46:40.000Z");
        assert_eq!(rfc3339_utc(1_767_225_600_000), "2026-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_utc(1_754_438_400_000), "2025-08-06T00:00:00.000Z");
    }

    #[test]
    fn leap_days_are_handled() {
        // 2024 is a leap year, so it has a 29 February.
        assert_eq!(rfc3339_utc(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
        // 2100 is divisible by 100 but not 400, so it is NOT a leap year. The
        // day after 28 February 2100 is 1 March; a naive `year % 4` rule would
        // print 29 February here.
        assert_eq!(rfc3339_utc(4_107_456_000_000), "2100-02-28T00:00:00.000Z");
        assert_eq!(rfc3339_utc(4_107_542_400_000), "2100-03-01T00:00:00.000Z");
        // 2000 is divisible by 400, so it IS a leap year.
        assert_eq!(rfc3339_utc(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn milliseconds_survive() {
        assert_eq!(rfc3339_utc(1_767_225_600_042), "2026-01-01T00:00:00.042Z");
    }

    #[test]
    fn the_last_second_of_a_day_does_not_roll_over_early() {
        assert_eq!(rfc3339_utc(1_767_225_599_999), "2025-12-31T23:59:59.999Z");
    }
}
