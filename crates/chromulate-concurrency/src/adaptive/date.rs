//! The three `HTTP-date` formats (RFC 9110 §5.6.7), for `Retry-After`.
//!
//! # Why this is not shared
//!
//! `chromulate-cache` has a fuller parser of the same three formats. It is
//! `pub(crate)` there, and reaching it would mean either making a cache crate's
//! internals public or pulling an RFC 9111 cache into every build that wants
//! adaptive concurrency. Neither is a trade this feature justifies, so the
//! parsing is repeated and the two are noted in each other's terms. If a third
//! caller ever needs it, that is the point at which it becomes a shared module
//! rather than the point at which it is guessed to be one.
//!
//! Rejecting garbage matters more than accepting exotica: a `Retry-After` that
//! is not a date must read as "no instruction" rather than as some instant near
//! the epoch, which would be a pause of minus fifty years.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Days since 1970-01-01 for a proleptic Gregorian civil date.
///
/// Howard Hinnant's `days_from_civil`
/// (<https://howardhinnant.github.io/date_algorithms.html>), which handles the
/// leap-year rule without a table. The same algorithm backs
/// `chromulate-cache`'s `HTTP-date` parser and `chromulate-cookie`'s
/// `cookie-date` parser.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted = (i64::from(month) + 9) % 12;
    let day_of_year = (153 * shifted + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn two_digits(token: &str) -> Option<u32> {
    if token.is_empty() || token.len() > 2 || !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

/// A month from its three-letter English abbreviation, one-based.
///
/// The comparison is against the whole token rather than its first three bytes,
/// so "November" is not a month and no separate length check is needed;
/// `chromulate-cache`'s parser compares a prefix and therefore does need one.
fn month_of(token: &str) -> Option<u32> {
    let lowered = token.to_ascii_lowercase();
    MONTHS
        .iter()
        .position(|month| *month == lowered)
        .map(|index| u32::try_from(index).unwrap_or(0) + 1)
}

/// A two- or four-digit year, normalised.
///
/// The two-digit form appears only in the obsolete RFC 850 format. The fixed
/// RFC 6265 window (70-99 to the 1900s, 00-69 to the 2000s) is used, matching
/// `chromulate-cookie` and `chromulate-cache`.
fn year_of(token: &str) -> Option<i64> {
    if !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match token.len() {
        2 => {
            let value: i64 = token.parse().ok()?;
            Some(if value >= 70 {
                1900 + value
            } else {
                2000 + value
            })
        }
        4 => token.parse().ok(),
        _ => None,
    }
}

fn time_of(token: &str) -> Option<(u32, u32, u32)> {
    let mut parts = token.split(':');
    let hour = two_digits(parts.next()?)?;
    let minute = two_digits(parts.next()?)?;
    let second = two_digits(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    // A leap second is 60, and a real `Date` header has carried one.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second))
}

/// Parses an `HTTP-date`, returning `None` for anything that is not one.
pub(super) fn http_date(input: &str) -> Option<SystemTime> {
    let input = input.trim();

    // `IMF-fixdate` and RFC 850 both put a comma after the weekday; `asctime`
    // has no comma at all. That single character tells the three apart.
    let (day, month, year, time) = match input.split_once(',') {
        Some((weekday, rest)) => {
            if weekday.trim().is_empty() {
                return None;
            }
            // "06 Nov 1994 08:49:37 GMT" and "06-Nov-94 08:49:37 GMT" differ
            // only in their separator, so both are split on either.
            let mut fields = rest.split(['-', ' ', '\t']).filter(|f| !f.is_empty());
            (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            )
        }
        None => {
            // "Sun Nov  6 08:49:37 1994", where the day is space-padded.
            let mut fields = input.split([' ', '\t']).filter(|f| !f.is_empty());
            let _weekday = fields.next()?;
            let month = fields.next()?;
            let day = fields.next()?;
            let time = fields.next()?;
            let year = fields.next()?;
            (day, month, year, time)
        }
    };

    let day = two_digits(day)?;
    let month = month_of(month)?;
    let year = year_of(year)?;
    let (hour, minute, second) = time_of(time)?;

    if day == 0 || day > 31 || year < 1601 {
        return None;
    }

    let seconds = days_from_civil(year, month, day) * 86_400
        + i64::from(hour) * 3600
        + i64::from(minute) * 60
        + i64::from(second);

    // Both arms are checked. A date before 1601 is rejected above and the
    // largest four-digit year is far inside what a `Duration` holds, but neither
    // fact is worth a panic if it stops being true.
    if seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch_secs(time: SystemTime) -> i64 {
        match time.duration_since(UNIX_EPOCH) {
            Ok(since) => i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
            Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
        }
    }

    #[test]
    fn the_three_formats_all_name_the_same_instant() {
        // RFC 9110 §5.6.7's own worked example.
        let imf = http_date("Sun, 06 Nov 1994 08:49:37 GMT").expect("IMF-fixdate parses");
        let rfc850 = http_date("Sunday, 06-Nov-94 08:49:37 GMT").expect("the RFC 850 form parses");
        let asctime = http_date("Sun Nov  6 08:49:37 1994").expect("the asctime form parses");

        assert_eq!(epoch_secs(imf), 784_111_777);
        assert_eq!(epoch_secs(rfc850), 784_111_777);
        assert_eq!(epoch_secs(asctime), 784_111_777);
    }

    #[test]
    fn anything_that_is_not_a_date_is_refused_rather_than_read_as_the_epoch() {
        for input in [
            "0",
            "-1",
            "",
            "Sun, 06 Nov 1994",
            "not a date",
            "Sun, 06 Xyz 1994 08:49:37 GMT",
            // The month is compared whole, so the spelled-out form is not a
            // month with three extra letters after it.
            "Sun, 06 November 1994 08:49:37 GMT",
            "Sun, 06 No 1994 08:49:37 GMT",
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:49:37 GMT",
            "Sun, 06 Nov 1994 08:60:37 GMT",
            ", 06 Nov 1994 08:49:37 GMT",
        ] {
            assert!(http_date(input).is_none(), "{input:?} is not a date");
        }
    }

    #[test]
    fn a_leap_second_is_accepted_because_real_servers_have_sent_one() {
        assert!(http_date("Sat, 31 Dec 2016 23:59:60 GMT").is_some());
    }

    #[test]
    fn a_date_far_in_the_future_parses_rather_than_overflowing() {
        let far = http_date("Fri, 31 Dec 9999 23:59:59 GMT").expect("a four-digit year parses");
        assert!(epoch_secs(far) > 253_000_000_000);
    }
}
