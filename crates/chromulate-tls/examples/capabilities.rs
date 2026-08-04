//! Prints what the linked rustls provider can actually do, and what a Chrome
//! engine built on it does and does not reproduce.
//!
//! ```text
//! cargo run -p chromulate-tls --example capabilities
//! cargo run -p chromulate-tls --example capabilities --features aws-lc-rs
//! ```
//!
//! Everything printed is read out of the provider and the built configuration
//! at run time, so this is a measurement of the binary in front of you rather
//! than a restatement of the documentation.

use chromulate_fingerprint::NamedGroup;
use chromulate_profile::Profile;
use chromulate_tls::{
    PROVIDER_NAME, STRUCTURAL_LIMITS, TlsEngine, available_cipher_suites, available_named_groups,
    supports_named_group,
};

fn main() -> Result<(), chromulate_core::Error> {
    let profile = Profile::chrome_stable();
    let engine = TlsEngine::new(&profile)?;
    let fidelity = engine.fidelity();

    println!("provider: {PROVIDER_NAME}");

    println!("\nnamed groups the provider implements, in its own order:");
    for group in available_named_groups() {
        println!("  {:#06x}", group.get());
    }
    println!(
        "\nX25519MLKEM768 ({:#06x}), which Chrome 151 offers first: {}",
        NamedGroup::X25519_MLKEM768.get(),
        if supports_named_group(NamedGroup::X25519_MLKEM768) {
            "available"
        } else {
            "NOT available"
        }
    );

    println!(
        "\ncipher suites the provider implements: {}",
        available_cipher_suites().len()
    );

    let (suites, suites_total) = fidelity.cipher_coverage();
    let (groups, groups_total) = fidelity.group_coverage();
    println!("\nagainst the {} profile:", profile.name);
    println!("  cipher suites offered: {suites} of {suites_total}");
    println!("  named groups offered:  {groups} of {groups_total}");
    println!("  alpn:                  {}", fidelity.alpn.join(", "));
    println!("  trust:                 {}", engine.trust_policy());
    println!("  target identity:       {}", engine.target_identity());

    if !fidelity.all_primitives_available() {
        println!("\ndropped, because the provider does not implement them:");
        for suite in &fidelity.dropped_cipher_suites {
            println!("  cipher suite {:#06x}", suite.get());
        }
        for group in &fidelity.dropped_groups {
            println!("  named group  {:#06x}", group.get());
        }
    }

    println!("\nthe emitted ClientHello is not the profile's, whatever the numbers above say:");
    for limit in STRUCTURAL_LIMITS {
        println!("  - {limit}");
    }

    Ok(())
}
