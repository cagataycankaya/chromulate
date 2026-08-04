//! The lenient `cookie-date` parser from RFC 6265 §5.1.1.
//!
//! Real `Expires` values are not RFC 1123 dates; servers still emit the obsolete RFC 850
//! and asctime formats, plus assorted hand-rolled variants. Rather than trying several
//! strict formats in sequence (and rejecting whatever doesn't match any of them), this
//! tokenises the string on delimiters and picks a time, day, month, and year out of the
//! tokens wherever they appear, exactly as RFC 6265 specifies and as every shipping
//! browser implements it.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// The delimiter set from RFC 6265 §5.1.1: tab, and the non-alphanumeric ranges that
/// surround digits and letters in ASCII. Everything else is a token character, including
/// `:` (so `08:49:37` survives as one token) and letters and digits (obviously).
fn is_delimiter(c: char) -> bool {
    matches!(c,
        '\u{09}'
        | '\u{20}'..='\u{2F}'
        | '\u{3B}'..='\u{40}'
        | '\u{5B}'..='\u{60}'
        | '\u{7B}'..='\u{7E}'
    )
}

/// The value of the run of ASCII digits at the start of `token`, and how many characters
/// that run occupies.
fn leading_digits(token: &str) -> Option<(u32, usize)> {
    let end = token
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(token.len());
    if end == 0 {
        return None;
    }
    let value: u32 = token[..end].parse().ok()?;
    Some((value, end))
}

/// Matches the `hms-time` production: `1*2DIGIT ":" 1*2DIGIT ":" 1*2DIGIT`, with any
/// trailing text after the seconds ignored (as RFC 6265 requires, to tolerate a glued-on
/// fractional second or time zone abbreviation).
fn try_time(token: &str) -> Option<(u32, u32, u32)> {
    let mut parts = token.splitn(3, ':');
    let hour = parts.next()?;
    let minute = parts.next()?;
    let rest = parts.next()?;

    if hour.is_empty() || hour.len() > 2 || !hour.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if minute.is_empty() || minute.len() > 2 || !minute.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (second, second_len) = leading_digits(rest)?;
    if second_len > 2 {
        return None;
    }

    Some((hour.parse().ok()?, minute.parse().ok()?, second))
}

/// Days since the Unix epoch (1970-01-01) for a proleptic Gregorian civil date.
///
/// Howard Hinnant's `days_from_civil` algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html>), which handles negative years
/// and the Gregorian leap-year rule without a lookup table.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (i64::from(m) + 9) % 12; // [0, 11], March = 0
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Converts a signed count of seconds since the Unix epoch to a [`SystemTime`], handling
/// dates before 1970.
pub(crate) fn epoch_seconds_to_system_time(seconds: i64) -> SystemTime {
    if seconds >= 0 {
        UNIX_EPOCH + Duration::from_secs(seconds as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
    }
}

/// Converts a [`SystemTime`] to a signed count of seconds since the Unix epoch, handling
/// dates before 1970.
pub(crate) fn system_time_to_epoch_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since_epoch) => since_epoch.as_secs() as i64,
        Err(before_epoch) => -(before_epoch.duration().as_secs() as i64),
    }
}

/// Parses a `cookie-date` per RFC 6265 §5.1.1, accepting the RFC 1123, obsolete RFC 850,
/// and asctime formats (and anything else that tokenises the same way), rather than one
/// strict grammar.
///
/// Two-digit years follow RFC 6265: 70-99 mean 1970-1999, 00-69 mean 2000-2069.
pub(crate) fn parse_cookie_date(input: &str) -> Option<SystemTime> {
    let mut found_time: Option<(u32, u32, u32)> = None;
    let mut found_day: Option<u32> = None;
    let mut found_month: Option<u32> = None;
    let mut found_year: Option<u32> = None;

    for token in input.split(is_delimiter).filter(|t| !t.is_empty()) {
        if found_time.is_none()
            && let Some(time) = try_time(token)
        {
            found_time = Some(time);
            continue;
        }
        if found_day.is_none()
            && let Some((value, len)) = leading_digits(token)
            && len <= 2
        {
            found_day = Some(value);
            continue;
        }
        if found_month.is_none()
            && let Some(prefix) = token.get(..3)
        {
            let prefix = prefix.to_ascii_lowercase();
            if let Some(index) = MONTHS.iter().position(|m| *m == prefix) {
                found_month = Some(index as u32 + 1);
                continue;
            }
        }
        if found_year.is_none()
            && let Some((value, len)) = leading_digits(token)
            && (len == 2 || len == 4)
        {
            found_year = Some(value);
        }
    }

    let (hour, minute, second) = found_time?;
    let day = found_day?;
    let month = found_month?;
    let mut year = found_year?;

    if hour > 23 || minute > 59 || second > 60 || day == 0 || day > 31 {
        return None;
    }

    if (70..=99).contains(&year) {
        year += 1900;
    } else if year <= 69 {
        year += 2000;
    }
    if year < 1601 {
        return None;
    }

    let days = days_from_civil(i64::from(year), month, day);
    let seconds =
        days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
    Some(epoch_seconds_to_system_time(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(t: SystemTime) -> i64 {
        system_time_to_epoch_seconds(t)
    }

    #[test]
    fn days_from_civil_matches_the_unix_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn rfc1123_style_date_parses_to_the_well_known_rfc6265_example_timestamp() {
        let parsed = parse_cookie_date("Sun, 06 Nov 1994 08:49:37 GMT").expect("should parse");
        assert_eq!(secs(parsed), 784_111_777);
    }

    #[test]
    fn obsolete_rfc850_style_date_with_a_two_digit_year_parses_the_same_instant() {
        let parsed = parse_cookie_date("Sunday, 06-Nov-94 08:49:37 GMT").expect("should parse");
        assert_eq!(secs(parsed), 784_111_777);
    }

    #[test]
    fn asctime_style_date_with_a_double_space_parses_the_same_instant() {
        let parsed = parse_cookie_date("Sun Nov  6 08:49:37 1994").expect("should parse");
        assert_eq!(secs(parsed), 784_111_777);
    }

    #[test]
    fn two_digit_years_from_70_to_99_roll_over_to_the_1900s() {
        let parsed = parse_cookie_date("06-Nov-70 00:00:00 GMT").expect("should parse");
        let year_1970_start = system_time_to_epoch_seconds(UNIX_EPOCH);
        assert!(secs(parsed) >= year_1970_start);
    }

    #[test]
    fn two_digit_years_from_00_to_69_roll_over_to_the_2000s() {
        let year_69 = parse_cookie_date("06-Nov-69 00:00:00 GMT").expect("should parse");
        let year_70 = parse_cookie_date("06-Nov-70 00:00:00 GMT").expect("should parse");
        // "69" means 2069, well after "70" which means 1970.
        assert!(secs(year_69) > secs(year_70));
    }

    #[test]
    fn a_date_missing_the_time_component_fails_to_parse() {
        assert!(parse_cookie_date("06 Nov 1994").is_none());
    }

    #[test]
    fn a_completely_unparseable_string_fails_to_parse() {
        assert!(parse_cookie_date("not a date at all").is_none());
    }

    #[test]
    fn day_of_month_out_of_range_fails_to_parse() {
        assert!(parse_cookie_date("Sun, 32 Nov 1994 08:49:37 GMT").is_none());
    }
}
