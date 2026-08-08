//! A ClientHello decoder shared by the integration tests that read real bytes.
//!
//! Extracted from `emitted_client_hello.rs` when a second backend arrived: the
//! decoding is a property of the wire format, not of rustls, and two tests that
//! decode the same bytes with two copies of the same parser would drift. What
//! stayed behind is the part that is backend-specific — how the bytes are
//! obtained at all.
//!
//! Every test binary that declares `mod common;` compiles this file separately
//! and reads a different subset of it, so the unused-code lint is silenced
//! here rather than each caller being made to touch fields it has no question
//! about.
#![allow(dead_code)]

/// The ClientHello fields these tests need, decoded from the wire.
#[derive(Debug)]
pub(crate) struct EmittedHello {
    pub(crate) record_version: u16,
    pub(crate) handshake_version: u16,
    pub(crate) cipher_suites: Vec<u16>,
    /// Extension code points in the order they were sent.
    pub(crate) extensions: Vec<u16>,
    pub(crate) server_name: Option<String>,
    pub(crate) alpn: Vec<String>,
    pub(crate) supported_groups: Vec<u16>,
    pub(crate) key_share_groups: Vec<u16>,
    pub(crate) supported_versions: Vec<u16>,
    pub(crate) signature_algorithms: Vec<u16>,
    pub(crate) certificate_compression: Vec<u16>,
    pub(crate) ec_point_formats: Vec<u8>,
    pub(crate) psk_key_exchange_modes: Vec<u8>,
}

/// A cursor that refuses to read past the end rather than panicking on a
/// malformed length, so a decoding bug shows up as a clear failure.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    pub(crate) fn take(&mut self, count: usize) -> &'a [u8] {
        assert!(
            self.remaining() >= count,
            "the ClientHello ended early: wanted {count} bytes, {} left",
            self.remaining()
        );
        let slice = &self.bytes[self.at..self.at + count];
        self.at += count;
        slice
    }

    pub(crate) fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    pub(crate) fn u16(&mut self) -> u16 {
        let bytes = self.take(2);
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    pub(crate) fn u24(&mut self) -> usize {
        let bytes = self.take(3);
        usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2])
    }

    /// Reads a vector with a one-byte length prefix.
    pub(crate) fn vec8(&mut self) -> &'a [u8] {
        let length = usize::from(self.u8());
        self.take(length)
    }

    /// Reads a vector with a two-byte length prefix.
    pub(crate) fn vec16(&mut self) -> &'a [u8] {
        let length = usize::from(self.u16());
        self.take(length)
    }
}

/// Reads every `u16` in a slice.
pub(crate) fn u16s(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect()
}

/// Decodes a TLS record holding a ClientHello.
pub(crate) fn parse(wire: &[u8]) -> EmittedHello {
    let mut reader = Reader::new(wire);
    assert_eq!(reader.u8(), 0x16, "the first record must be a handshake");
    let record_version = reader.u16();
    let record_length = usize::from(reader.u16());
    assert_eq!(
        record_length,
        reader.remaining(),
        "the ClientHello should arrive as one whole record"
    );

    assert_eq!(
        reader.u8(),
        0x01,
        "the handshake message must be ClientHello"
    );
    let body_length = reader.u24();
    assert_eq!(body_length, reader.remaining());

    let handshake_version = reader.u16();
    let _random = reader.take(32);
    let _session_id = reader.vec8();
    let cipher_suites = u16s(reader.vec16());
    let _compression_methods = reader.vec8();

    let mut hello = EmittedHello {
        record_version,
        handshake_version,
        cipher_suites,
        extensions: Vec::new(),
        server_name: None,
        alpn: Vec::new(),
        supported_groups: Vec::new(),
        key_share_groups: Vec::new(),
        supported_versions: Vec::new(),
        signature_algorithms: Vec::new(),
        certificate_compression: Vec::new(),
        ec_point_formats: Vec::new(),
        psk_key_exchange_modes: Vec::new(),
    };

    let extensions = reader.vec16();
    let mut reader = Reader::new(extensions);
    while reader.remaining() > 0 {
        let id = reader.u16();
        let body = reader.vec16();
        hello.extensions.push(id);
        let mut body = Reader::new(body);

        match id {
            0x0000 => {
                let mut list = Reader::new(body.vec16());
                let kind = list.u8();
                assert_eq!(kind, 0, "only host_name is defined for SNI");
                let name = list.vec16();
                hello.server_name =
                    Some(String::from_utf8(name.to_vec()).expect("SNI must be ASCII"));
            }
            0x000a => hello.supported_groups = u16s(body.vec16()),
            0x000b => hello.ec_point_formats = body.vec8().to_vec(),
            0x000d => hello.signature_algorithms = u16s(body.vec16()),
            0x0010 => {
                let list = body.vec16();
                let mut list = Reader::new(list);
                while list.remaining() > 0 {
                    let protocol = list.vec8();
                    hello
                        .alpn
                        .push(String::from_utf8(protocol.to_vec()).expect("ALPN must be ASCII"));
                }
            }
            0x001b => hello.certificate_compression = u16s(body.vec8()),
            0x002b => hello.supported_versions = u16s(body.vec8()),
            0x002d => hello.psk_key_exchange_modes = body.vec8().to_vec(),
            0x0033 => {
                let shares = body.vec16();
                let mut shares = Reader::new(shares);
                while shares.remaining() > 0 {
                    hello.key_share_groups.push(shares.u16());
                    let _key = shares.vec16();
                }
            }
            _ => {}
        }
    }

    hello
}
