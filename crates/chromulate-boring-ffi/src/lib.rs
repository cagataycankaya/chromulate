//! The BoringSSL calls `boring` 5.1.0 does not wrap, wrapped safely.
//!
//! # Why this crate exists at all
//!
//! Chrome 151's ClientHello carries `status_request` (extension `0x0005`) and
//! `application_settings` (ALPS, extension `0x44cd`). Reproducing it therefore
//! means asking BoringSSL for both. `boring` 5.1.0 exposes neither on its safe
//! API: measured on 2026-08-08, a connector configured through the safe API
//! alone emitted 14 of the profile's 16 extensions, and those two were the
//! absentees.
//!
//! The three C functions that supply them are present in `boring-sys` and take
//! raw pointers, so calling them is `unsafe`. That is the whole of this crate:
//! three calls, each one line, each with the invariant it relies on written
//! above it.
//!
//! # Why it is a crate rather than three lines in `chromulate-tls`
//!
//! `chromulate-tls` is `#![forbid(unsafe_code)]`, and `forbid` cannot be
//! relaxed at a call site — which is the reason to use it. Putting these calls
//! in that crate would mean demoting it to `deny` and opening the whole TLS
//! implementation, the one that handles keys, to a lint escape that nothing
//! narrows. Here the exception is a crate with three functions and no state,
//! and `chromulate-tls` keeps its guarantee intact.
//!
//! # What would remove the need for it
//!
//! `boring2` wraps all three safely today. It is not what this workspace
//! depends on, because its crates.io line has been frozen since 2025-08-14 with
//! development moved to a renamed repository, and it vendors the pre-relicense
//! OpenSSL/SSLeay licence mix — a TLS dependency that stops receiving security
//! fixes being the worse of the two risks. If `boring` grows safe wrappers, or
//! if that trade changes, this crate is deleted and its three call sites become
//! ordinary method calls.

#![doc(html_root_url = "https://docs.rs/chromulate-boring-ffi/0.3.0")]
#![warn(missing_docs)]

use boring::ssl::{Ssl, SslContextBuilder};
use foreign_types_shared::ForeignTypeRef;

/// Asks for `status_request` (`0x0005`) by enabling OCSP stapling.
///
/// Chrome sends the extension; BoringSSL emits it once stapling is enabled.
///
/// ```no_run
/// use boring::ssl::{SslConnector, SslMethod};
///
/// let mut builder = SslConnector::builder(SslMethod::tls())?;
/// chromulate_boring_ffi::enable_ocsp_stapling(&mut builder);
/// # Ok::<(), boring::error::ErrorStack>(())
/// ```
pub fn enable_ocsp_stapling(builder: &mut SslContextBuilder) {
    // SAFETY: `as_ptr` returns the `SSL_CTX *` this builder owns, which is live
    // for the borrow. `SSL_CTX_enable_ocsp_stapling` only sets a flag on it,
    // reads nothing through any other pointer, and cannot fail.
    unsafe {
        boring_sys::SSL_CTX_enable_ocsp_stapling(builder.as_ptr());
    }
}

/// Adds one ALPS protocol with no settings payload, as Chrome does for `h2`.
///
/// Returns `false` when BoringSSL rejects the protocol, which it does for a
/// protocol that is not in the ALPN list. The caller decides what that means;
/// this crate does not turn a C return code into a policy.
///
/// ```no_run
/// # fn example(ssl: &mut boring::ssl::Ssl) {
/// let accepted = chromulate_boring_ffi::add_application_settings(ssl, b"h2");
/// # let _ = accepted;
/// # }
/// ```
#[must_use]
pub fn add_application_settings(ssl: &mut Ssl, protocol: &[u8]) -> bool {
    // SAFETY: `as_ptr` returns the live `SSL *` borrowed for this call.
    // `protocol` is read for `protocol.len()` bytes during the call and not
    // retained — BoringSSL copies it. The settings pointer is null with length
    // zero, which the function documents as "no settings", and is what the
    // Chrome 151 capture shows on the wire.
    let rc = unsafe {
        boring_sys::SSL_add_application_settings(
            ssl.as_ptr(),
            protocol.as_ptr(),
            protocol.len(),
            std::ptr::null(),
            0,
        )
    };
    rc == 1
}

/// Selects the new ALPS codepoint, `0x44cd`.
///
/// There are two: the draft `0x4469` and the current `0x44cd`. The Chrome 151
/// capture records `0x44cd`, and BoringSSL defaults to the other one, so this
/// call is what makes the emitted extension id match the capture rather than
/// merely being "ALPS".
///
/// ```no_run
/// # fn example(ssl: &mut boring::ssl::Ssl) {
/// chromulate_boring_ffi::use_new_alps_codepoint(ssl);
/// # }
/// ```
pub fn use_new_alps_codepoint(ssl: &mut Ssl) {
    // SAFETY: `as_ptr` returns the live `SSL *` borrowed for this call. The
    // function stores a boolean on it and reads nothing else.
    unsafe {
        boring_sys::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), 1);
    }
}
