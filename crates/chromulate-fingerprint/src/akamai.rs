//! The Akamai HTTP/2 fingerprint.

use md5::{Digest, Md5};

use crate::http2::Http2Spec;

/// Computes the Akamai HTTP/2 fingerprint string.
///
/// The format is `settings|window_update|priority|pseudo_header_order`, for
/// example `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`. The third field
/// lists PRIORITY frames as `stream:exclusive:depends_on:weight` and is a bare
/// `0` when the client sends none, which is what modern Chrome does.
#[must_use]
pub fn akamai_http2(spec: &Http2Spec) -> String {
    let settings = spec
        .settings
        .iter()
        .map(|setting| format!("{}:{}", setting.id.get(), setting.value))
        .collect::<Vec<_>>()
        .join(";");

    let priority = if spec.priority_frames.is_empty() {
        "0".to_owned()
    } else {
        spec.priority_frames
            .iter()
            .map(|frame| {
                format!(
                    "{}:{}:{}:{}",
                    frame.stream_id,
                    u8::from(frame.exclusive),
                    frame.depends_on,
                    frame.weight
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };

    format!(
        "{settings}|{}|{priority}|{}",
        spec.connection_window_update,
        spec.pseudo_header_order.code()
    )
}

/// Hashes an Akamai fingerprint string with MD5.
#[must_use]
pub fn akamai_http2_hash(fingerprint: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(fingerprint.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http2::{PriorityFrame, PseudoHeaderOrder, Setting, SettingId};

    fn spec() -> Http2Spec {
        Http2Spec {
            settings: vec![
                Setting::new(SettingId::HEADER_TABLE_SIZE, 65536),
                Setting::new(SettingId::ENABLE_PUSH, 0),
            ],
            connection_window_update: 15_663_105,
            priority_frames: Vec::new(),
            headers_priority: None,
            pseudo_header_order: PseudoHeaderOrder::CHROME,
        }
    }

    #[test]
    fn a_client_that_sends_no_priority_frames_renders_a_bare_zero() {
        assert_eq!(akamai_http2(&spec()), "1:65536;2:0|15663105|0|m,a,s,p");
    }

    #[test]
    fn priority_frames_render_as_stream_exclusive_dependency_weight() {
        let mut spec = spec();
        spec.priority_frames = vec![
            PriorityFrame {
                stream_id: 3,
                exclusive: false,
                depends_on: 0,
                weight: 201,
            },
            PriorityFrame {
                stream_id: 5,
                exclusive: true,
                depends_on: 3,
                weight: 101,
            },
        ];
        assert_eq!(
            akamai_http2(&spec),
            "1:65536;2:0|15663105|3:0:0:201,5:1:3:101|m,a,s,p"
        );
    }
}
