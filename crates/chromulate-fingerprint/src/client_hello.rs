//! The ClientHello model that JA3 and JA4 are computed from.

use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::error::SpecError;
use crate::grease::GreaseValue;
use crate::ids::{
    CertificateCompression, CipherSuite, EcPointFormat, ExtensionId, NamedGroup,
    PskKeyExchangeMode, SignatureScheme, TlsVersion, Transport,
};

/// The set of extensions a client offers, without any ordering.
///
/// Order is deliberately not part of this type: Chrome permutes its extensions
/// on every connection, so a profile that froze one order would describe a
/// browser that does not exist. GREASE is likewise not a member — it is a
/// placement rule, see [`GreasePlacement`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Vec<ExtensionId>", into = "Vec<ExtensionId>")]
pub struct ExtensionSet {
    ids: Vec<ExtensionId>,
}

impl ExtensionSet {
    /// Builds a set, discarding duplicates and any GREASE values.
    pub fn new(ids: impl IntoIterator<Item = ExtensionId>) -> Self {
        let mut ids: Vec<ExtensionId> = ids.into_iter().filter(|id| !id.is_grease()).collect();
        ids.sort_unstable();
        ids.dedup();
        Self { ids }
    }

    /// Returns the extensions in ascending code point order, the order JA4 hashes.
    #[must_use]
    pub fn sorted(&self) -> &[ExtensionId] {
        &self.ids
    }

    /// Iterates the extensions in ascending code point order.
    pub fn iter(&self) -> impl Iterator<Item = ExtensionId> + '_ {
        self.ids.iter().copied()
    }

    /// Returns `true` when the extension is offered.
    #[must_use]
    pub fn contains(&self, id: ExtensionId) -> bool {
        self.ids.binary_search(&id).is_ok()
    }

    /// Returns the number of extensions offered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Returns `true` when no extensions are offered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Adds an extension, returning `true` when it was not already present.
    ///
    /// GREASE values are rejected, because GREASE is placement rather than
    /// membership.
    pub fn insert(&mut self, id: ExtensionId) -> bool {
        if id.is_grease() {
            return false;
        }
        match self.ids.binary_search(&id) {
            Ok(_) => false,
            Err(index) => {
                self.ids.insert(index, id);
                true
            }
        }
    }

    /// Removes an extension, returning `true` when it was present.
    pub fn remove(&mut self, id: ExtensionId) -> bool {
        match self.ids.binary_search(&id) {
            Ok(index) => {
                self.ids.remove(index);
                true
            }
            Err(_) => false,
        }
    }

    /// Returns this set with one more extension, for building spec variants.
    #[must_use]
    pub fn with(mut self, id: ExtensionId) -> Self {
        self.insert(id);
        self
    }
}

impl From<Vec<ExtensionId>> for ExtensionSet {
    fn from(ids: Vec<ExtensionId>) -> Self {
        Self::new(ids)
    }
}

impl From<ExtensionSet> for Vec<ExtensionId> {
    fn from(set: ExtensionSet) -> Self {
        set.ids
    }
}

impl FromIterator<ExtensionId> for ExtensionSet {
    fn from_iter<T: IntoIterator<Item = ExtensionId>>(iter: T) -> Self {
        Self::new(iter)
    }
}

/// One connection's extension list, in the order it goes on the wire.
///
/// Constructing this type is the only way to state a wire order, and the
/// constructor enforces the two rules a real ClientHello cannot break:
/// `pre_shared_key` is last (RFC 8446 section 4.2.11), and GREASE only ever
/// occupies the edges of the list. Anything that holds a `WireExtensionOrder`
/// therefore holds an order a browser could actually have sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<ExtensionId>", into = "Vec<ExtensionId>")]
pub struct WireExtensionOrder(Vec<ExtensionId>);

impl WireExtensionOrder {
    /// Validates and wraps a wire order.
    ///
    /// # Errors
    ///
    /// Returns [`SpecError`] when an extension repeats, when `pre_shared_key`
    /// is not last, or when a GREASE value sits anywhere but the first or last
    /// slot.
    pub fn new(ids: Vec<ExtensionId>) -> Result<Self, SpecError> {
        let len = ids.len();
        for (index, id) in ids.iter().enumerate() {
            if ids[..index].contains(id) {
                return Err(SpecError::DuplicateExtension { value: id.get() });
            }
            if *id == ExtensionId::PRE_SHARED_KEY && index + 1 != len {
                return Err(SpecError::PreSharedKeyNotLast { index, len });
            }
        }

        let last_non_psk = ids
            .iter()
            .rposition(|id| *id != ExtensionId::PRE_SHARED_KEY);
        for (index, id) in ids.iter().enumerate() {
            if id.is_grease() && index != 0 && Some(index) != last_non_psk {
                return Err(SpecError::MisplacedGrease {
                    value: id.get(),
                    index,
                });
            }
        }

        Ok(Self(ids))
    }

    /// Wraps an order that the caller has already produced under the invariants.
    ///
    /// Only the generator in [`ClientHelloSpec`] uses this, and
    /// `generated_orders_always_satisfy_the_public_constructor` re-validates a
    /// large sample of its output through [`WireExtensionOrder::new`].
    pub(crate) fn trusted(ids: Vec<ExtensionId>) -> Self {
        Self(ids)
    }

    /// Returns the order as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[ExtensionId] {
        &self.0
    }

    /// Iterates the order, GREASE included.
    pub fn iter(&self) -> impl Iterator<Item = ExtensionId> + '_ {
        self.0.iter().copied()
    }

    /// Iterates the order with GREASE removed, the form JA3 hashes.
    pub fn without_grease(&self) -> impl Iterator<Item = ExtensionId> + '_ {
        self.0.iter().copied().filter(|id| !id.is_grease())
    }

    /// Returns the number of extensions in the order, GREASE included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the order is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<ExtensionId>> for WireExtensionOrder {
    type Error = SpecError;

    fn try_from(ids: Vec<ExtensionId>) -> Result<Self, Self::Error> {
        Self::new(ids)
    }
}

impl From<WireExtensionOrder> for Vec<ExtensionId> {
    fn from(order: WireExtensionOrder) -> Self {
        order.0
    }
}

/// The extensions a shuffled order holds in place, validated on construction.
///
/// Chrome pins nothing, so the shipped profile carries an empty set. Pinning
/// exists for the browsers that do keep some extensions in fixed positions,
/// which is the whole mechanism for modelling a non-Chrome client.
///
/// The fields are private and the constructor is fallible for the same reason
/// [`WireExtensionOrder`] validates: an order that a real client could not have
/// sent must be unrepresentable, not merely discouraged. A public field could
/// be written through a `&mut` match even behind `#[non_exhaustive]`, so the
/// only ways in are [`ShufflePins::new`] and deserialisation, which routes
/// through it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ShufflePinsDocument")]
pub struct ShufflePins {
    pinned_first: Vec<ExtensionId>,
    pinned_last: Vec<ExtensionId>,
}

/// The deserialisation shape of [`ShufflePins`], before validation.
#[derive(Deserialize)]
struct ShufflePinsDocument {
    #[serde(default)]
    pinned_first: Vec<ExtensionId>,
    #[serde(default)]
    pinned_last: Vec<ExtensionId>,
}

impl TryFrom<ShufflePinsDocument> for ShufflePins {
    type Error = SpecError;

    fn try_from(document: ShufflePinsDocument) -> Result<Self, Self::Error> {
        Self::new(document.pinned_first, document.pinned_last)
    }
}

impl ShufflePins {
    /// Nothing pinned, which is what Chrome does.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            pinned_first: Vec::new(),
            pinned_last: Vec::new(),
        }
    }

    /// Validates and builds a pin list.
    ///
    /// # Errors
    ///
    /// Returns [`SpecError::UnpinnableExtension`] for `pre_shared_key` or a
    /// GREASE value, whose positions the wire format fixes and the generator
    /// assigns, and [`SpecError::DuplicateExtension`] when one extension
    /// appears twice across the two lists.
    pub fn new(
        pinned_first: Vec<ExtensionId>,
        pinned_last: Vec<ExtensionId>,
    ) -> Result<Self, SpecError> {
        let mut seen: Vec<ExtensionId> = Vec::with_capacity(pinned_first.len() + pinned_last.len());
        for id in pinned_first.iter().chain(pinned_last.iter()).copied() {
            if id == ExtensionId::PRE_SHARED_KEY {
                return Err(SpecError::UnpinnableExtension {
                    value: id.get(),
                    reason: "RFC 8446 4.2.11 requires pre_shared_key to be the final extension",
                });
            }
            if id.is_grease() {
                return Err(SpecError::UnpinnableExtension {
                    value: id.get(),
                    reason: "GREASE brackets the extension list rather than sitting inside it",
                });
            }
            if seen.contains(&id) {
                return Err(SpecError::DuplicateExtension { value: id.get() });
            }
            seen.push(id);
        }

        Ok(Self {
            pinned_first,
            pinned_last,
        })
    }

    /// The extensions held at the front of the list, in order.
    #[must_use]
    pub fn first(&self) -> &[ExtensionId] {
        &self.pinned_first
    }

    /// The extensions held at the back of the list, in order.
    #[must_use]
    pub fn last(&self) -> &[ExtensionId] {
        &self.pinned_last
    }

    /// Returns `true` when nothing is pinned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pinned_first.is_empty() && self.pinned_last.is_empty()
    }
}

/// How a profile turns its extension set into a wire order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtensionOrder {
    /// The same order on every connection.
    ///
    /// Use this for clients that do not permute, and to reproduce one observed
    /// connection exactly.
    Fixed(WireExtensionOrder),

    /// A fresh permutation per connection, as Chrome does.
    ///
    /// The pinned extensions keep their place; everything else is shuffled
    /// between them.
    Shuffled(ShufflePins),
}

impl ExtensionOrder {
    /// A shuffle with nothing pinned, which is what Chrome does.
    #[must_use]
    pub const fn shuffled() -> Self {
        Self::Shuffled(ShufflePins::none())
    }

    /// A shuffle that holds some extensions in place.
    ///
    /// # Errors
    ///
    /// As [`ShufflePins::new`].
    pub fn shuffled_with_pins(
        pinned_first: Vec<ExtensionId>,
        pinned_last: Vec<ExtensionId>,
    ) -> Result<Self, SpecError> {
        Ok(Self::Shuffled(ShufflePins::new(pinned_first, pinned_last)?))
    }

    /// Returns `true` when the order changes from connection to connection.
    #[must_use]
    pub const fn is_shuffled(&self) -> bool {
        matches!(self, Self::Shuffled(_))
    }
}

/// Where a client places GREASE values.
///
/// Each flag corresponds to one entry of the capture's `grease_positions`
/// list. The extension flag covers both the first and the last extension slot,
/// because a client that GREASEs its extension list always brackets it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GreasePlacement {
    /// A GREASE cipher suite is offered first.
    pub cipher_suites: bool,
    /// GREASE brackets the extension list.
    pub extensions: bool,
    /// A GREASE group is offered first in `supported_groups`.
    pub supported_groups: bool,
    /// A GREASE group is offered first in `key_share`.
    pub key_shares: bool,
    /// A GREASE version is offered first in `supported_versions`.
    pub supported_versions: bool,
}

impl GreasePlacement {
    /// No GREASE anywhere.
    pub const NONE: Self = Self {
        cipher_suites: false,
        extensions: false,
        supported_groups: false,
        key_shares: false,
        supported_versions: false,
    };

    /// GREASE in every position this model knows about.
    pub const ALL: Self = Self {
        cipher_suites: true,
        extensions: true,
        supported_groups: true,
        key_shares: true,
        supported_versions: true,
    };
}

/// Everything an observer can derive a TLS fingerprint from.
///
/// The lists are stored *without* GREASE; GREASE is described by
/// [`ClientHelloSpec::grease`] and injected when a wire order is generated.
/// That split is what lets one spec describe every connection a browser makes
/// rather than a single captured handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHelloSpec {
    /// The transport carrying the handshake, which JA4 records first.
    pub transport: Transport,
    /// The version in the record layer header.
    pub record_version: TlsVersion,
    /// The version in the handshake header, which JA3 records.
    pub handshake_version: TlsVersion,
    /// The `supported_versions` list, highest first.
    pub supported_versions: Vec<TlsVersion>,
    /// Cipher suites in wire order. Chrome keeps this order stable.
    pub cipher_suites: Vec<CipherSuite>,
    /// The extensions offered, as a set.
    pub extensions: ExtensionSet,
    /// How the set becomes a wire order.
    pub extension_order: ExtensionOrder,
    /// The `supported_groups` list, in wire order.
    pub supported_groups: Vec<NamedGroup>,
    /// The groups a key share is actually sent for, in wire order.
    pub key_share_groups: Vec<NamedGroup>,
    /// The `signature_algorithms` list; JA4 hashes it in this order.
    pub signature_algorithms: Vec<SignatureScheme>,
    /// ALPN protocol identifiers, most preferred first.
    pub alpn: Vec<String>,
    /// ALPS protocol identifiers (`application_settings`).
    pub alps: Vec<String>,
    /// Certificate compression algorithms offered.
    pub certificate_compression: Vec<CertificateCompression>,
    /// PSK key exchange modes offered.
    pub psk_key_exchange_modes: Vec<PskKeyExchangeMode>,
    /// EC point formats offered, the fifth JA3 field.
    pub ec_point_formats: Vec<EcPointFormat>,
    /// Where GREASE goes.
    pub grease: GreasePlacement,
}

impl ClientHelloSpec {
    /// Returns `true` when the client sends SNI, which JA4 encodes as `d`.
    #[must_use]
    pub fn has_sni(&self) -> bool {
        self.extensions.contains(ExtensionId::SERVER_NAME)
    }

    /// Returns the most preferred ALPN protocol, if any.
    #[must_use]
    pub fn first_alpn(&self) -> Option<&str> {
        self.alpn.first().map(String::as_str)
    }

    /// Returns the version JA4 reports: the highest offered in
    /// `supported_versions`, falling back to the handshake version.
    #[must_use]
    pub fn effective_version(&self) -> TlsVersion {
        self.supported_versions
            .iter()
            .copied()
            .max()
            .unwrap_or(self.handshake_version)
    }

    /// Iterates the cipher suites with GREASE removed, the form both
    /// fingerprints hash.
    pub fn ciphers_without_grease(&self) -> impl Iterator<Item = CipherSuite> + '_ {
        self.cipher_suites
            .iter()
            .copied()
            .filter(|suite| !suite.is_grease())
    }

    /// Iterates the supported groups with GREASE removed.
    pub fn groups_without_grease(&self) -> impl Iterator<Item = NamedGroup> + '_ {
        self.supported_groups
            .iter()
            .copied()
            .filter(|group| !group.is_grease())
    }

    /// Returns this spec with `pre_shared_key` added, as sent when a session
    /// ticket is available.
    #[must_use]
    pub fn with_pre_shared_key(&self) -> Self {
        let mut spec = self.clone();
        spec.extensions.insert(ExtensionId::PRE_SHARED_KEY);
        if let ExtensionOrder::Fixed(order) = &spec.extension_order {
            let mut ids: Vec<ExtensionId> = order
                .iter()
                .filter(|id| *id != ExtensionId::PRE_SHARED_KEY)
                .collect();
            ids.push(ExtensionId::PRE_SHARED_KEY);
            spec.extension_order = ExtensionOrder::Fixed(WireExtensionOrder::trusted(ids));
        }
        spec
    }

    /// Returns this spec without `pre_shared_key`.
    #[must_use]
    pub fn without_pre_shared_key(&self) -> Self {
        let mut spec = self.clone();
        spec.extensions.remove(ExtensionId::PRE_SHARED_KEY);
        if let ExtensionOrder::Fixed(order) = &spec.extension_order {
            let ids: Vec<ExtensionId> = order
                .iter()
                .filter(|id| *id != ExtensionId::PRE_SHARED_KEY)
                .collect();
            spec.extension_order = ExtensionOrder::Fixed(WireExtensionOrder::trusted(ids));
        }
        spec
    }

    /// Produces the cipher suites as they go on the wire, GREASE included.
    ///
    /// Only the leading GREASE suite varies; the rest of the list is never
    /// reordered, which is what makes the JA4 cipher component stable across
    /// connections.
    pub fn wire_cipher_suites<R: Rng>(&self, rng: &mut R) -> Vec<CipherSuite> {
        let mut suites = Vec::with_capacity(self.cipher_suites.len() + 1);
        if self.grease.cipher_suites {
            suites.push(CipherSuite::from(GreaseValue::draw(rng)));
        }
        suites.extend(self.ciphers_without_grease());
        suites
    }

    /// Produces the cipher suites as they go on the wire, from a seed.
    #[must_use]
    pub fn wire_cipher_suites_seeded(&self, seed: u64) -> Vec<CipherSuite> {
        self.wire_cipher_suites(&mut StdRng::seed_from_u64(seed))
    }

    /// Produces one connection's extension order.
    pub fn wire_extension_order<R: Rng>(&self, rng: &mut R) -> WireExtensionOrder {
        match &self.extension_order {
            ExtensionOrder::Fixed(order) => order.clone(),
            ExtensionOrder::Shuffled(pins) => {
                let mut body = self.shuffled_body(pins);
                body.shuffle(rng);
                let grease = self
                    .grease
                    .extensions
                    .then(|| GreaseValue::draw_pair(rng))
                    .map(|(first, last)| (ExtensionId::from(first), ExtensionId::from(last)));
                WireExtensionOrder::trusted(self.assemble(pins, body, grease))
            }
        }
    }

    /// Produces one connection's extension order from a seed, so tests and
    /// reproductions can pin the permutation.
    #[must_use]
    pub fn wire_extension_order_seeded(&self, seed: u64) -> WireExtensionOrder {
        self.wire_extension_order(&mut StdRng::seed_from_u64(seed))
    }

    /// Returns a deterministic stand-in for the wire order.
    ///
    /// A shuffled profile has no single wire order, but [`crate::ja3()`] has to
    /// be a pure function of the spec, so it uses this: pinned extensions in
    /// place, the rest in ascending code point order, and the lowest two GREASE
    /// values at the edges. For a shuffled profile the resulting JA3 is one of
    /// many the browser produces — which is the point of JA3 being unstable —
    /// so use [`ClientHelloSpec::wire_extension_order`] when you need the JA3 of
    /// a specific connection.
    #[must_use]
    pub fn reference_extension_order(&self) -> WireExtensionOrder {
        match &self.extension_order {
            ExtensionOrder::Fixed(order) => order.clone(),
            ExtensionOrder::Shuffled(pins) => {
                let body = self.shuffled_body(pins);
                let grease = self.grease.extensions.then(|| {
                    (
                        ExtensionId::from(GreaseValue::ALL[0]),
                        ExtensionId::from(GreaseValue::ALL[1]),
                    )
                });
                WireExtensionOrder::trusted(self.assemble(pins, body, grease))
            }
        }
    }

    /// The extensions that are free to move, in ascending order.
    fn shuffled_body(&self, pins: &ShufflePins) -> Vec<ExtensionId> {
        self.extensions
            .iter()
            .filter(|id| {
                *id != ExtensionId::PRE_SHARED_KEY
                    && !pins.first().contains(id)
                    && !pins.last().contains(id)
            })
            .collect()
    }

    /// Lays the pieces out in wire order under the invariants of
    /// [`WireExtensionOrder`].
    ///
    /// The result is valid by construction rather than by checking: the body
    /// excludes both pin lists and `pre_shared_key`, and [`ShufflePins`] has
    /// already refused a duplicate pin, a pinned `pre_shared_key` and a pinned
    /// GREASE value. That is what lets the trailing `pre_shared_key` be
    /// appended unconditionally without it landing in the list twice or
    /// anywhere but last.
    fn assemble(
        &self,
        pins: &ShufflePins,
        body: Vec<ExtensionId>,
        grease: Option<(ExtensionId, ExtensionId)>,
    ) -> Vec<ExtensionId> {
        let mut order = Vec::with_capacity(self.extensions.len() + 2);
        if let Some((first, _)) = grease {
            order.push(first);
        }
        order.extend_from_slice(pins.first());
        order.extend(body);
        order.extend_from_slice(pins.last());
        if let Some((_, last)) = grease {
            order.push(last);
        }
        if self.extensions.contains(ExtensionId::PRE_SHARED_KEY) {
            order.push(ExtensionId::PRE_SHARED_KEY);
        }
        order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ClientHelloSpec {
        ClientHelloSpec {
            transport: Transport::Tcp,
            record_version: TlsVersion::Tls12,
            handshake_version: TlsVersion::Tls12,
            supported_versions: vec![TlsVersion::Tls13, TlsVersion::Tls12],
            cipher_suites: vec![
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            ],
            extensions: ExtensionSet::new([
                ExtensionId::SERVER_NAME,
                ExtensionId::SUPPORTED_GROUPS,
                ExtensionId::SIGNATURE_ALGORITHMS,
                ExtensionId::ALPN,
                ExtensionId::SUPPORTED_VERSIONS,
                ExtensionId::KEY_SHARE,
                ExtensionId::SESSION_TICKET,
            ]),
            extension_order: ExtensionOrder::shuffled(),
            supported_groups: vec![NamedGroup::X25519],
            key_share_groups: vec![NamedGroup::X25519],
            signature_algorithms: vec![SignatureScheme::ECDSA_SECP256R1_SHA256],
            alpn: vec!["h2".to_owned()],
            alps: vec!["h2".to_owned()],
            certificate_compression: vec![CertificateCompression::Brotli],
            psk_key_exchange_modes: vec![PskKeyExchangeMode::PskDheKe],
            ec_point_formats: vec![EcPointFormat::Uncompressed],
            grease: GreasePlacement::ALL,
        }
    }

    #[test]
    fn an_extension_set_ignores_insertion_order_and_grease() {
        let a = ExtensionSet::new([ExtensionId::ALPN, ExtensionId::SERVER_NAME]);
        let b = ExtensionSet::new([
            ExtensionId::SERVER_NAME,
            ExtensionId::ALPN,
            ExtensionId::from(GreaseValue::ALL[3]),
            ExtensionId::ALPN,
        ]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn a_wire_order_rejects_pre_shared_key_anywhere_but_last() {
        let error =
            WireExtensionOrder::new(vec![ExtensionId::PRE_SHARED_KEY, ExtensionId::SERVER_NAME])
                .expect_err("pre_shared_key in first place must be rejected");
        assert_eq!(error, SpecError::PreSharedKeyNotLast { index: 0, len: 2 });
    }

    #[test]
    fn a_wire_order_rejects_grease_in_the_middle_of_the_list() {
        let error = WireExtensionOrder::new(vec![
            ExtensionId::SERVER_NAME,
            ExtensionId::from(GreaseValue::ALL[0]),
            ExtensionId::ALPN,
        ])
        .expect_err("GREASE in the middle must be rejected");
        assert!(matches!(error, SpecError::MisplacedGrease { .. }));
    }

    #[test]
    fn a_wire_order_rejects_a_repeated_extension() {
        let error = WireExtensionOrder::new(vec![ExtensionId::ALPN, ExtensionId::ALPN])
            .expect_err("a repeated extension must be rejected");
        assert_eq!(error, SpecError::DuplicateExtension { value: 0x0010 });
    }

    #[test]
    fn a_wire_order_accepts_grease_brackets_with_pre_shared_key_after_them() {
        let order = WireExtensionOrder::new(vec![
            ExtensionId::from(GreaseValue::ALL[0]),
            ExtensionId::SERVER_NAME,
            ExtensionId::from(GreaseValue::ALL[1]),
            ExtensionId::PRE_SHARED_KEY,
        ])
        .expect("GREASE brackets followed by pre_shared_key is a legal order");
        assert_eq!(order.len(), 4);
    }

    #[test]
    fn generated_orders_always_satisfy_the_public_constructor() {
        let spec = spec();
        let resumed = spec.with_pre_shared_key();
        for seed in 0..256 {
            for candidate in [
                spec.wire_extension_order_seeded(seed),
                resumed.wire_extension_order_seeded(seed),
            ] {
                WireExtensionOrder::new(candidate.as_slice().to_vec())
                    .expect("the generator must only produce orders the constructor accepts");
            }
        }
    }

    /// Pin lists reachable from outside the crate that would each break a wire
    /// invariant if the generator honoured them: `pre_shared_key`, which has to
    /// be last; the same extension at both ends, which duplicates it; and a
    /// GREASE value, which the generator places itself.
    const HOSTILE_PIN_DOCUMENTS: [&str; 3] = [
        r#"{"Shuffled":{"pinned_first":[41],"pinned_last":[]}}"#,
        r#"{"Shuffled":{"pinned_first":[16],"pinned_last":[16]}}"#,
        r#"{"Shuffled":{"pinned_first":[2570],"pinned_last":[]}}"#,
    ];

    #[test]
    fn a_shuffled_order_serialises_to_the_shape_a_stored_profile_already_uses() {
        let order = ExtensionOrder::shuffled();
        let json = serde_json::to_string(&order).expect("an order serialises");

        assert_eq!(json, r#"{"Shuffled":{"pinned_first":[],"pinned_last":[]}}"#);
        assert_eq!(
            serde_json::from_str::<ExtensionOrder>(&json).expect("and reads back"),
            order
        );
    }

    #[test]
    fn a_shuffle_cannot_pin_an_extension_whose_place_the_wire_format_already_fixes() {
        let psk = ExtensionOrder::shuffled_with_pins(vec![ExtensionId::PRE_SHARED_KEY], Vec::new())
            .expect_err("pre_shared_key has to be last, so it cannot be pinned first");
        assert!(
            matches!(psk, SpecError::UnpinnableExtension { value, .. } if value == 0x0029),
            "{psk:?}"
        );

        let grease = ExtensionOrder::shuffled_with_pins(
            Vec::new(),
            vec![ExtensionId::from(GreaseValue::ALL[0])],
        )
        .expect_err("GREASE brackets the list, so it cannot be pinned");
        assert!(
            matches!(grease, SpecError::UnpinnableExtension { .. }),
            "{grease:?}"
        );

        let both =
            ExtensionOrder::shuffled_with_pins(vec![ExtensionId::ALPN], vec![ExtensionId::ALPN])
                .expect_err("an extension pinned at both ends would be emitted twice");
        assert_eq!(both, SpecError::DuplicateExtension { value: 0x0010 });
    }

    #[test]
    fn a_shuffle_can_still_pin_the_extensions_a_non_chrome_browser_holds_in_place() {
        let mut spec = spec();
        spec.extension_order = ExtensionOrder::shuffled_with_pins(
            vec![ExtensionId::SERVER_NAME],
            vec![ExtensionId::SESSION_TICKET, ExtensionId::ALPN],
        )
        .expect("pinning ordinary extensions is the point of the feature");
        let resumed = spec.with_pre_shared_key();

        for seed in 0..256 {
            for candidate in [
                spec.wire_extension_order_seeded(seed),
                resumed.wire_extension_order_seeded(seed),
            ] {
                let ids = candidate.as_slice();
                assert_eq!(
                    ids[1],
                    ExtensionId::SERVER_NAME,
                    "seed {seed}: the front pin sits right after the GREASE bracket"
                );
                WireExtensionOrder::new(ids.to_vec())
                    .expect("a pinned order must satisfy the validating constructor");
            }
        }
    }

    #[test]
    fn no_reachable_pin_list_makes_the_generator_produce_an_order_its_constructor_rejects() {
        for document in HOSTILE_PIN_DOCUMENTS {
            let Ok(order) = serde_json::from_str::<ExtensionOrder>(document) else {
                // Refusing the pins is the other legitimate answer.
                continue;
            };

            let mut spec = spec();
            spec.extension_order = order;
            let resumed = spec.with_pre_shared_key();
            for candidate in [
                spec.wire_extension_order_seeded(0),
                spec.reference_extension_order(),
                resumed.wire_extension_order_seeded(0),
                resumed.reference_extension_order(),
            ] {
                let ids = candidate.as_slice().to_vec();
                if let Err(error) = WireExtensionOrder::new(ids) {
                    panic!(
                        "{document} was accepted and then generated an order the validating \
                         constructor rejects: {error:?}\n  order = {:?}",
                        candidate.as_slice()
                    );
                }
            }
        }
    }

    #[test]
    fn shuffling_changes_the_order_but_never_the_set() {
        let spec = spec();
        let first = spec.wire_extension_order_seeded(1);
        let second = spec.wire_extension_order_seeded(2);
        assert_ne!(
            first.as_slice(),
            second.as_slice(),
            "two seeds should not produce the same permutation"
        );

        let mut left: Vec<ExtensionId> = first.without_grease().collect();
        let mut right: Vec<ExtensionId> = second.without_grease().collect();
        left.sort_unstable();
        right.sort_unstable();
        assert_eq!(left, right);
        assert_eq!(left, spec.extensions.sorted());
    }

    #[test]
    fn shuffling_never_reorders_the_cipher_suites() {
        let spec = spec();
        let baseline: Vec<CipherSuite> = spec.ciphers_without_grease().collect();
        for seed in 0..64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let wire = spec.wire_cipher_suites(&mut rng);
            assert!(wire[0].is_grease(), "the first suite should be GREASE");
            assert_eq!(&wire[1..], baseline.as_slice());
        }
    }

    #[test]
    fn grease_brackets_every_generated_order_and_psk_stays_last() {
        let resumed = spec().with_pre_shared_key();
        for seed in 0..64 {
            let order = resumed.wire_extension_order_seeded(seed);
            let ids = order.as_slice();
            assert!(ids[0].is_grease(), "seed {seed}: first slot must be GREASE");
            assert_eq!(
                ids[ids.len() - 1],
                ExtensionId::PRE_SHARED_KEY,
                "seed {seed}: pre_shared_key must be last"
            );
            assert!(
                ids[ids.len() - 2].is_grease(),
                "seed {seed}: the last slot before pre_shared_key must be GREASE"
            );
            assert_ne!(
                ids[0],
                ids[ids.len() - 2],
                "seed {seed}: the two GREASE values must differ"
            );
        }
    }

    #[test]
    fn adding_pre_shared_key_keeps_a_fixed_order_valid() {
        let mut base = spec();
        base.extension_order = ExtensionOrder::Fixed(
            WireExtensionOrder::new(vec![ExtensionId::SERVER_NAME, ExtensionId::ALPN])
                .expect("a two extension order is valid"),
        );
        let resumed = base.with_pre_shared_key();
        let ExtensionOrder::Fixed(order) = &resumed.extension_order else {
            panic!("with_pre_shared_key must keep a fixed order fixed");
        };
        WireExtensionOrder::new(order.as_slice().to_vec())
            .expect("the rebuilt fixed order must still be valid");
        assert_eq!(order.as_slice().last(), Some(&ExtensionId::PRE_SHARED_KEY));
    }
}
