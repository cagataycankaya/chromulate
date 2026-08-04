//! Building the final header name order: the profile's captured order plus
//! whatever a specific request needs that the capture had no occasion to
//! record.

/// Whether `order` already lists `name`.
pub(crate) fn contains(order: &[String], name: &str) -> bool {
    order.iter().any(|entry| entry == name)
}

/// Inserts `name` directly before `anchor`, or at the end when `anchor` is
/// not present in `order`.
///
/// Does nothing when `order` already lists `name`. The positions this crate
/// picks for `host`, `origin`, `sec-fetch-user` and `referer` are general
/// protocol knowledge, not capture data; a capture that recorded the header
/// itself is the better evidence for where it goes, and inserting a second
/// copy would put the name on the wire twice — two `Host` headers is a shape
/// many origins and intermediaries reject outright.
pub(crate) fn insert_before(order: &mut Vec<String>, anchor: &str, name: &str) {
    if contains(order, name) {
        return;
    }
    let index = order
        .iter()
        .position(|entry| entry == anchor)
        .unwrap_or(order.len());
    order.insert(index, name.to_owned());
}

/// Inserts `name` directly after `anchor`, or at the end when `anchor` is
/// not present in `order`.
///
/// Does nothing when `order` already lists `name`, for the reason given on
/// [`insert_before`].
pub(crate) fn insert_after(order: &mut Vec<String>, anchor: &str, name: &str) {
    if contains(order, name) {
        return;
    }
    let index = order
        .iter()
        .position(|entry| entry == anchor)
        .map_or(order.len(), |position| position + 1);
    order.insert(index, name.to_owned());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_before_lands_immediately_ahead_of_the_anchor() {
        let mut order = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        insert_before(&mut order, "b", "x");
        assert_eq!(order, vec!["a", "x", "b", "c"]);
    }

    #[test]
    fn insert_after_lands_immediately_behind_the_anchor() {
        let mut order = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        insert_after(&mut order, "b", "x");
        assert_eq!(order, vec!["a", "b", "x", "c"]);
    }

    #[test]
    fn a_missing_anchor_appends_at_the_end() {
        let mut order = vec!["a".to_owned()];
        insert_before(&mut order, "missing", "x");
        insert_after(&mut order, "also-missing", "y");
        assert_eq!(order, vec!["a", "x", "y"]);
    }

    #[test]
    fn a_name_the_order_already_lists_keeps_the_position_it_already_has() {
        let mut order = vec!["a".to_owned(), "x".to_owned(), "b".to_owned()];
        insert_before(&mut order, "a", "x");
        insert_after(&mut order, "b", "x");
        assert_eq!(order, vec!["a", "x", "b"]);
    }
}
