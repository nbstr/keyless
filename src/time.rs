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

/// Whole days from today (UTC) until `date`, written `YYYY-MM-DD`.
///
/// Negative when the date has passed, `0` on the day itself.
///
/// # Why this lives beside `rfc3339_utc` and not next to its caller
///
/// It is the inverse of [`civil_from_days`], and the two have to agree about
/// leap years or a credential reported as having a week left is a credential
/// that expired yesterday. A second civil-date implementation written where it
/// happened to be needed is exactly the drift this module was created to avoid.
///
/// # Errors
///
/// A sentence naming what is wrong with the spelling. Deliberately not a
/// silent `None`: the caller is a health check, and a date it could not read
/// must read as a fault rather than as "nothing to report".
pub fn days_until_utc(date: &str) -> Result<i64, String> {
    let malformed =
        || format!("`{date}` is not a date; write it as YYYY-MM-DD, the day the token stops");

    let parts: Vec<&str> = date.trim().split('-').collect();
    let [year, month, day] = parts.as_slice() else {
        return Err(malformed());
    };
    if year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return Err(malformed());
    }
    let year: i64 = year.parse().map_err(|_| malformed())?;
    let month: u32 = month.parse().map_err(|_| malformed())?;
    let day: u32 = day.parse().map_err(|_| malformed())?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(malformed());
    }

    let target = days_from_civil(year, month, day);
    // Round-tripped rather than trusted: `2026-02-31` parses as three numbers
    // in range and is not a day. Hinnant's arithmetic maps it onto 2 March
    // without complaining, so the only way to reject it is to convert back.
    if civil_from_days(target) != (year, month, day) {
        return Err(format!("`{date}` is not a day that exists"));
    }

    let today = (now_unix_millis() / 1000) as i64 / 86_400;
    Ok(target - today)
}

/// A proleptic Gregorian date to days since the Unix epoch.
///
/// Howard Hinnant's `days_from_civil`, the exact inverse of
/// [`civil_from_days`] below.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = i64::from(if month > 2 { month - 3 } else { month + 9 }); // March-based
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
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
    use super::{days_from_civil, days_until_utc, rfc3339_utc};

    #[test]
    fn the_two_civil_date_conversions_are_inverses() {
        // The property that makes `days_until_utc` trustworthy. Without it a
        // credential reported as having a week left could be one that expired
        // yesterday, and nothing would say so.
        for (y, m, d) in [
            (1970, 1, 1),
            (2000, 2, 29),
            (2024, 2, 29),
            (2026, 1, 1),
            (2100, 3, 1),
            (2400, 12, 31),
        ] {
            assert_eq!(
                super::civil_from_days(days_from_civil(y, m, d)),
                (y, m, d),
                "{y:04}-{m:02}-{d:02}"
            );
        }
        // Written out rather than derived, so both directions are pinned to a
        // value neither function produced.
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 1, 1), 20_454);
    }

    #[test]
    fn a_date_that_is_not_a_day_is_refused_rather_than_rounded() {
        // Hinnant's arithmetic maps 31 February onto 2 March without
        // complaining, so three numbers in range is not enough. Read as a
        // date, a token declared to expire on a day that does not exist would
        // report a comfortable margin.
        for bad in [
            "2026-02-31",
            "2026-13-01",
            "26-01-01",
            "2026-1-1",
            "",
            "soon",
        ] {
            assert!(days_until_utc(bad).is_err(), "`{bad}` was accepted");
        }
        // The control: a real day is read, and the count moves with the date
        // rather than being any number at all.
        let near = days_until_utc("2026-01-01").expect("a real day");
        let far = days_until_utc("2027-01-01").expect("a real day");
        assert_eq!(far - near, 365);
    }

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
