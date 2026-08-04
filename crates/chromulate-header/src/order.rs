//! Building the final header name order: the profile's captured order plus
//! whatever a specific request needs that the capture had no occasion to
//! record.
//!
//! The helpers are generic over the entry type so the engine can order its
//! prepared slots without copying names: anything that can say what it is
//! called participates.

/// An order entry that knows its lowercase wire name.
pub(crate) trait Named {
    fn order_name(&self) -> &str;
}

impl Named for String {
    fn order_name(&self) -> &str {
        self
    }
}

/// Whether `order` already lists `name`.
pub(crate) fn contains<T: Named>(order: &[T], name: &str) -> bool {
    order.iter().any(|entry| entry.order_name() == name)
}

/// Inserts `entry` directly before `anchor`, or at the end when `anchor` is
/// not present in `order`.
///
/// Does nothing when `order` already lists `entry`'s name. The positions this
/// crate picks for `host`, `origin`, `sec-fetch-user` and `referer` are
/// general protocol knowledge, not capture data; a capture that recorded the
/// header itself is the better evidence for where it goes, and inserting a
/// second copy would put the name on the wire twice — two `Host` headers is a
/// shape many origins and intermediaries reject outright.
pub(crate) fn insert_before<T: Named>(order: &mut Vec<T>, anchor: &str, entry: T) {
    if contains(order, entry.order_name()) {
        return;
    }
    let index = order
        .iter()
        .position(|held| held.order_name() == anchor)
        .unwrap_or(order.len());
    order.insert(index, entry);
}

/// Inserts `entry` directly after `anchor`, or at the end when `anchor` is
/// not present in `order`.
///
/// Does nothing when `order` already lists `entry`'s name, for the reason
/// given on [`insert_before`].
pub(crate) fn insert_after<T: Named>(order: &mut Vec<T>, anchor: &str, entry: T) {
    if contains(order, entry.order_name()) {
        return;
    }
    let index = order
        .iter()
        .position(|held| held.order_name() == anchor)
        .map_or(order.len(), |position| position + 1);
    order.insert(index, entry);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_before_lands_immediately_ahead_of_the_anchor() {
        let mut order = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        insert_before(&mut order, "b", "x".to_owned());
        assert_eq!(order, vec!["a", "x", "b", "c"]);
    }

    #[test]
    fn insert_after_lands_immediately_behind_the_anchor() {
        let mut order = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        insert_after(&mut order, "b", "x".to_owned());
        assert_eq!(order, vec!["a", "b", "x", "c"]);
    }

    #[test]
    fn a_missing_anchor_appends_at_the_end() {
        let mut order = vec!["a".to_owned()];
        insert_before(&mut order, "missing", "x".to_owned());
        insert_after(&mut order, "also-missing", "y".to_owned());
        assert_eq!(order, vec!["a", "x", "y"]);
    }

    #[test]
    fn a_name_the_order_already_lists_keeps_the_position_it_already_has() {
        let mut order = vec!["a".to_owned(), "x".to_owned(), "b".to_owned()];
        insert_before(&mut order, "a", "x".to_owned());
        insert_after(&mut order, "b", "x".to_owned());
        assert_eq!(order, vec!["a", "x", "b"]);
    }
}
