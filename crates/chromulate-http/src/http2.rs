//! Translating a profile's HTTP/2 preface into hyper's builder, and reporting
//! what did not survive the translation.
//!
//! The Akamai HTTP/2 fingerprint is four fields: the SETTINGS entries in order,
//! the connection-level WINDOW_UPDATE increment, the PRIORITY frames, and the
//! pseudo-header order. hyper exposes knobs for some of that and hard-codes the
//! rest. Rather than set what can be set and stay quiet about the remainder,
//! every setting the profile names is either applied or recorded in
//! [`Http2Fidelity::unsupported`], so a caller can print the difference next to
//! what an echo endpoint reports.

use std::fmt;

use chromulate_fingerprint::{Http2Spec, PseudoHeaderOrder, SettingId};
use hyper::client::conn::http2;

/// The connection flow-control window a peer starts with, before any
/// WINDOW_UPDATE (RFC 9113 section 6.9.2).
///
/// hyper is configured with a target window size and derives the increment it
/// sends; the profile records the increment. This is the constant that converts
/// between them.
pub const DEFAULT_CONNECTION_WINDOW: u32 = 65_535;

/// One thing the profile asks for that this hyper build cannot do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedSetting {
    /// What was asked for, in the fingerprint's own vocabulary.
    pub wanted: String,
    /// What happens instead.
    pub actual: String,
}

impl UnsupportedSetting {
    fn new(wanted: impl Into<String>, actual: impl Into<String>) -> Self {
        Self {
            wanted: wanted.into(),
            actual: actual.into(),
        }
    }
}

impl fmt::Display for UnsupportedSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.wanted, self.actual)
    }
}

/// The gap between the profile's HTTP/2 preface and the one hyper will send.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Http2Fidelity {
    /// SETTINGS entries applied to the builder, in the profile's order.
    pub applied: Vec<(SettingId, u32)>,
    /// Everything the profile specifies that hyper does not let this crate set.
    pub unsupported: Vec<UnsupportedSetting>,
    /// The Akamai fingerprint the profile is aiming at.
    pub target: String,
}

impl Http2Fidelity {
    /// Whether every part of the profile's preface was reproducible.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.unsupported.is_empty()
    }
}

impl fmt::Display for Http2Fidelity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "target={} applied={} unsupported={}",
            self.target,
            self.applied.len(),
            self.unsupported.len()
        )
    }
}

/// Applies a profile's HTTP/2 shape to a hyper builder.
///
/// Returns what could not be applied. hyper's builder is mutated in place
/// because that is the shape hyper offers.
pub fn configure<E>(builder: &mut http2::Builder<E>, spec: &Http2Spec) -> Http2Fidelity
where
    E: Clone,
{
    let mut fidelity = Http2Fidelity {
        target: chromulate_fingerprint::akamai_http2(spec),
        ..Http2Fidelity::default()
    };

    // hyper always emits SETTINGS_MAX_FRAME_SIZE from its own 16 KiB default.
    // Chrome does not send it at all, and an entry the profile never listed is
    // as visible to a fingerprinter as a wrong value, so the default is cleared
    // first and re-set below only if the profile asks for it.
    builder.max_frame_size(None);

    let mut saw_max_header_list_size = false;
    let mut saw_initial_window_size = false;

    for setting in &spec.settings {
        let value = setting.value;
        match setting.id {
            SettingId::HEADER_TABLE_SIZE => {
                builder.header_table_size(Some(value));
                fidelity.applied.push((setting.id, value));
            }
            SettingId::MAX_CONCURRENT_STREAMS => {
                builder.max_concurrent_streams(Some(value));
                fidelity.applied.push((setting.id, value));
            }
            SettingId::INITIAL_WINDOW_SIZE => {
                builder.initial_stream_window_size(Some(value));
                saw_initial_window_size = true;
                fidelity.applied.push((setting.id, value));
            }
            SettingId::MAX_FRAME_SIZE => {
                builder.max_frame_size(Some(value));
                fidelity.applied.push((setting.id, value));
            }
            SettingId::MAX_HEADER_LIST_SIZE => {
                builder.max_header_list_size(value);
                saw_max_header_list_size = true;
                fidelity.applied.push((setting.id, value));
            }
            SettingId::ENABLE_PUSH => {
                // hyper hard-codes `enable_push(false)` when it builds the h2
                // client, so a profile asking for 0 is satisfied without being
                // settable, and one asking for 1 cannot be honoured.
                if value == 0 {
                    fidelity.applied.push((setting.id, value));
                } else {
                    fidelity.unsupported.push(UnsupportedSetting::new(
                        "SETTINGS_ENABLE_PUSH=1",
                        "hyper hard-codes enable_push(false) on the h2 client",
                    ));
                }
            }
            other => {
                fidelity.unsupported.push(UnsupportedSetting::new(
                    format!("SETTINGS id {other}={value}"),
                    "hyper's h2 client builder exposes no setter for it",
                ));
            }
        }
    }

    if !saw_max_header_list_size {
        fidelity.unsupported.push(UnsupportedSetting::new(
            "no SETTINGS_MAX_HEADER_LIST_SIZE entry",
            "hyper always emits one; its setter takes a u32 and cannot be cleared",
        ));
    }
    if !saw_initial_window_size {
        fidelity.unsupported.push(UnsupportedSetting::new(
            "no SETTINGS_INITIAL_WINDOW_SIZE entry",
            "hyper always emits one; passing None leaves its 2 MiB default in place",
        ));
    }

    if !is_ascending_by_id(spec) {
        fidelity.unsupported.push(UnsupportedSetting::new(
            "the profile's SETTINGS order",
            "h2 emits settings in ascending identifier order, whatever order they were set in",
        ));
    }

    builder.initial_connection_window_size(Some(
        spec.connection_window_update
            .saturating_add(DEFAULT_CONNECTION_WINDOW),
    ));

    if spec.pseudo_header_order != PseudoHeaderOrder::CHROME {
        fidelity.unsupported.push(UnsupportedSetting::new(
            format!("pseudo-header order {}", spec.pseudo_header_order.code()),
            "h2 emits :method :scheme :authority :path from a fixed struct order",
        ));
    } else {
        // Chrome's order is :method :authority :scheme :path; h2's is
        // :method :scheme :authority :path. Even the profile this crate ships
        // cannot be reproduced here.
        fidelity.unsupported.push(UnsupportedSetting::new(
            "pseudo-header order m,a,s,p",
            "h2 emits m,s,a,p from a fixed struct order in frame::headers::Pseudo",
        ));
    }

    if !spec.priority_frames.is_empty() {
        fidelity.unsupported.push(UnsupportedSetting::new(
            format!("{} PRIORITY frame(s)", spec.priority_frames.len()),
            "hyper's h2 client sends none and exposes no way to send them",
        ));
    }

    if spec.headers_priority.is_some() {
        fidelity.unsupported.push(UnsupportedSetting::new(
            "priority fields on the first HEADERS frame",
            "hyper sends HEADERS without the priority flag and exposes no way to set it",
        ));
    }

    fidelity
}

fn is_ascending_by_id(spec: &Http2Spec) -> bool {
    spec.settings
        .windows(2)
        .all(|pair| pair[0].id.get() <= pair[1].id.get())
}

#[cfg(test)]
mod tests {
    use chromulate_fingerprint::Setting;
    use chromulate_profile::Profile;
    use hyper_util::rt::TokioExecutor;

    use super::*;

    fn configure_spec(spec: &Http2Spec) -> Http2Fidelity {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        configure(&mut builder, spec)
    }

    #[test]
    fn every_setting_the_chrome_profile_lists_is_applied() {
        let profile = Profile::chrome_stable();
        let fidelity = configure_spec(&profile.http2);

        let applied: Vec<(u16, u32)> = fidelity
            .applied
            .iter()
            .map(|(id, value)| (id.get(), *value))
            .collect();
        assert_eq!(
            applied,
            vec![(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)],
            "the capture's four settings must all reach the builder"
        );
    }

    #[test]
    fn the_pseudo_header_order_is_reported_as_unreproducible_even_for_the_shipped_profile() {
        let fidelity = configure_spec(&Profile::chrome_stable().http2);
        assert!(
            fidelity
                .unsupported
                .iter()
                .any(|gap| gap.wanted.contains("pseudo-header order")),
            "h2's fixed m,s,a,p order is a gap that must never be silently swallowed: {:?}",
            fidelity.unsupported
        );
        assert!(!fidelity.is_exact());
    }

    #[test]
    fn the_headers_frame_priority_the_capture_recorded_is_reported_as_unreproducible() {
        let profile = Profile::chrome_stable();
        assert!(
            profile.http2.headers_priority.is_some(),
            "the Chrome capture records HEADERS priority fields"
        );
        let fidelity = configure_spec(&profile.http2);
        assert!(
            fidelity
                .unsupported
                .iter()
                .any(|gap| gap.wanted.contains("first HEADERS frame"))
        );
    }

    #[test]
    fn a_setting_hyper_has_no_setter_for_is_reported_rather_than_dropped() {
        let mut spec = Profile::chrome_stable().http2;
        spec.settings
            .push(Setting::new(SettingId::NO_RFC7540_PRIORITIES, 1));

        let fidelity = configure_spec(&spec);
        assert!(
            fidelity
                .unsupported
                .iter()
                .any(|gap| gap.wanted.contains("SETTINGS id 9=1")),
            "{:?}",
            fidelity.unsupported
        );
    }

    #[test]
    fn a_profile_asking_for_server_push_is_reported_because_hyper_refuses_it() {
        let mut spec = Profile::chrome_stable().http2;
        for setting in &mut spec.settings {
            if setting.id == SettingId::ENABLE_PUSH {
                setting.value = 1;
            }
        }
        let fidelity = configure_spec(&spec);
        assert!(
            fidelity
                .unsupported
                .iter()
                .any(|gap| gap.wanted.contains("ENABLE_PUSH=1"))
        );
    }

    #[test]
    fn a_settings_order_h2_cannot_emit_is_reported() {
        let mut spec = Profile::chrome_stable().http2;
        spec.settings.reverse();
        let fidelity = configure_spec(&spec);
        assert!(
            fidelity
                .unsupported
                .iter()
                .any(|gap| gap.wanted.contains("SETTINGS order")),
            "{:?}",
            fidelity.unsupported
        );
    }

    #[test]
    fn the_chrome_settings_order_is_ascending_so_h2_can_reproduce_it() {
        assert!(
            is_ascending_by_id(&Profile::chrome_stable().http2),
            "h2 sorts by identifier, so a non-ascending capture would be unreproducible"
        );
        let fidelity = configure_spec(&Profile::chrome_stable().http2);
        assert!(
            !fidelity
                .unsupported
                .iter()
                .any(|gap| gap.wanted.contains("SETTINGS order"))
        );
    }

    #[test]
    fn the_connection_window_target_is_the_captured_increment_plus_the_protocol_default() {
        let profile = Profile::chrome_stable();
        assert_eq!(profile.http2.connection_window_update, 15_663_105);
        assert_eq!(
            profile.http2.connection_window_update + DEFAULT_CONNECTION_WINDOW,
            15_728_640,
            "15 MiB, which is the target hyper has to be given to emit Chrome's increment"
        );
    }

    #[test]
    fn the_target_akamai_fingerprint_is_carried_for_comparison() {
        let fidelity = configure_spec(&Profile::chrome_stable().http2);
        assert_eq!(
            fidelity.target,
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        );
    }
}
