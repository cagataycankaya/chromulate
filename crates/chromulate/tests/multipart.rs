//! `multipart/form-data` bodies, checked against the bytes that reach a server.
//!
//! Every expected byte sequence in this file comes from
//! `tests/data/chrome-151-multipart.txt`, which records what Chrome 151 actually
//! sent for the same inputs. The assertions are on the request body the test
//! server received, not on anything the builder returns, so a builder that
//! agrees with itself but not with the wire format fails here.

#![cfg(feature = "multipart")]

mod common;

use chromulate::dns::StaticResolver;
use chromulate::header::Bytes;
use chromulate::multipart::{Form, Part};
use chromulate::{Client, Error};
use common::{Recorded, Reply, TestServer};

fn client_for(server: &TestServer, host: &str) -> Client {
    Client::builder()
        .resolver(StaticResolver::empty().with_host(host.to_owned(), vec![server.addr()]))
        .build()
        .expect("the client must build")
}

/// The boundary the request declared, taken from its `Content-Type`.
///
/// Reading it back from the header rather than from the `Form` is deliberate:
/// the header and the body are two independent outputs of the encoder, and a
/// test that took the boundary from the encoder could not notice them
/// disagreeing.
fn boundary_of(received: &Recorded) -> String {
    let content_type = received
        .header("content-type")
        .expect("a multipart request declares its content type");
    let (kind, boundary) = content_type
        .split_once("; boundary=")
        .unwrap_or_else(|| panic!("`{content_type}` carries no boundary parameter"));
    assert_eq!(kind, "multipart/form-data");
    boundary.to_owned()
}

/// How many parts the received body actually contains, by counting delimiters.
fn part_count(received: &Recorded, boundary: &str) -> usize {
    received
        .body_text()
        .matches(&format!("--{boundary}\r\n"))
        .count()
}

// ------------------------------------------------------------ the wire form

#[tokio::test]
async fn the_wire_form_matches_the_captured_chrome_layout() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/upload"))
        .multipart(
            Form::new()
                .text("plain", "ordinary")
                .part(
                    "upload",
                    Part::bytes(Bytes::from_static(b"file body bytes\n"))
                        .file_name("report.txt")
                        .mime_str("text/plain"),
                )
                .text("after", "tail"),
        )
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    let b = boundary_of(received);

    // Section 4 of the capture: the first delimiter carries no leading CRLF,
    // every later one is preceded by the CRLF that ends the previous content,
    // and the closing delimiter is `--boundary--` followed by CRLF.
    assert_eq!(
        received.body_text(),
        format!(
            "--{b}\r\n\
             Content-Disposition: form-data; name=\"plain\"\r\n\
             \r\n\
             ordinary\r\n\
             --{b}\r\n\
             Content-Disposition: form-data; name=\"upload\"; filename=\"report.txt\"\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             file body bytes\n\r\n\
             --{b}\r\n\
             Content-Disposition: form-data; name=\"after\"\r\n\
             \r\n\
             tail\r\n\
             --{b}--\r\n"
        )
    );
}

#[tokio::test]
async fn a_part_without_a_filename_carries_no_content_type() {
    // Capture section 3: Chrome emits `Content-Type` on a part if and only if
    // that part has a filename.
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().text("plain", "ordinary"))
        .send()
        .await
        .expect("the request must succeed");

    let body = server.received()[0].body_text();
    assert!(
        !body.to_ascii_lowercase().contains("content-type:"),
        "a nameless-file part must not declare a content type: {body:?}"
    );
}

#[tokio::test]
async fn a_named_part_without_an_explicit_mime_defaults_to_octet_stream() {
    // Capture section 3: a part with a filename always carries a content type,
    // falling back to `application/octet-stream`.
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().part("upload", Part::text("abc").file_name("noextension")))
        .send()
        .await
        .expect("the request must succeed");

    assert!(
        server.received()[0]
            .body_text()
            .contains("Content-Type: application/octet-stream\r\n"),
        "{:?}",
        server.received()[0].body_text()
    );
}

#[tokio::test]
async fn parts_arrive_in_the_order_they_were_added() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(
            Form::new()
                .text("first", "1")
                .part("second", Part::text("2").file_name("f.bin"))
                .text("third", "3"),
        )
        .send()
        .await
        .expect("the request must succeed");

    let body = server.received()[0].body_text();
    let first = body
        .find("name=\"first\"")
        .expect("the first part is present");
    let second = body
        .find("name=\"second\"")
        .expect("the second part is present");
    let third = body
        .find("name=\"third\"")
        .expect("the third part is present");
    assert!(
        first < second && second < third,
        "a file part must not be hoisted past the text parts: {body:?}"
    );
}

// ------------------------------------------------------------ the boundary

#[tokio::test]
async fn the_boundary_has_the_shape_chrome_draws() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    for _ in 0..2 {
        client
            .post(server.url_for("example.test", "/"))
            .multipart(Form::new().text("a", "b"))
            .send()
            .await
            .expect("the request must succeed");
    }

    let received = server.received();
    let first = boundary_of(&received[0]);
    let second = boundary_of(&received[1]);

    // Capture section 1: a 22-character literal prefix and a 16-character tail
    // drawn from [0-9A-Za-z], redrawn per request.
    for boundary in [&first, &second] {
        assert_eq!(boundary.len(), 38, "{boundary}");
        let tail = boundary
            .strip_prefix("----WebKitFormBoundary")
            .unwrap_or_else(|| panic!("`{boundary}` lacks the captured prefix"));
        assert_eq!(tail.len(), 16, "{boundary}");
        assert!(
            tail.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "the tail must stay inside [0-9A-Za-z]: {boundary}"
        );
    }
    assert_ne!(first, second, "the boundary must be redrawn per request");
}

#[tokio::test]
async fn a_part_whose_content_is_itself_a_multipart_document_adds_no_parts() {
    // The realistic attack on boundary selection: a field value that is a
    // complete, well-formed multipart document. If the outer boundary ever
    // collided with the inner one, the server would read extra parts.
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    let smuggled = "------WebKitFormBoundaryAAAAAAAAAAAAAAAA\r\n\
                    Content-Disposition: form-data; name=\"smuggled\"\r\n\
                    \r\n\
                    surprise\r\n\
                    ------WebKitFormBoundaryAAAAAAAAAAAAAAAA--\r\n";

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().text("outer", smuggled).text("tail", "t"))
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    let boundary = boundary_of(received);
    assert_eq!(
        part_count(received, &boundary),
        2,
        "the smuggled document must stay inert content: {:?}",
        received.body_text()
    );
    assert!(
        received.body_text().contains(smuggled),
        "the content must be sent verbatim"
    );
}

// A boundary hidden in a filename or a media type belongs here by subject, but
// not by construction: an integration test cannot drive it, because the encoder
// draws a random boundary and a colliding draw is a 62^-16 event, so the
// assertions would pass whether or not the search ran. Both live as unit tests
// against `encode_with`, which injects the colliding candidate:
// `a_boundary_found_in_a_header_block_is_redrawn` and
// `a_boundary_hidden_in_a_filename_or_a_media_type_is_redrawn_too`.

// ------------------------------------------------- header injection surface

#[tokio::test]
async fn a_quote_in_a_field_name_cannot_forge_a_disposition_parameter() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().text("he said \"hi\"; filename=\"evil.txt\"", "value"))
        .send()
        .await
        .expect("the request must succeed");

    let body = server.received()[0].body_text();

    // Capture section 2: the quotes become `%22`, and everything else -- the
    // semicolon, the spaces, the equals sign -- is passed through literally.
    assert!(
        body.contains(
            "Content-Disposition: form-data; name=\"he said %22hi%22; filename=%22evil.txt%22\"\r\n"
        ),
        "{body:?}"
    );
    // The forged parameter must not exist as a parameter. This is the
    // assertion that matters: a parser reading this part sees no filename.
    assert!(
        !body.contains("filename=\"evil.txt\""),
        "the quoted string must not have been closed early: {body:?}"
    );
}

#[tokio::test]
async fn crlf_in_a_filename_cannot_forge_a_header_or_an_extra_part() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    // A filename that tries to close the header block, add a header, and open
    // a second part of its own.
    let hostile = "a.txt\r\nX-Injected: yes\r\n\r\nforged\r\n--x--\r\n";

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().part("upload", Part::text("real").file_name(hostile)))
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    let body = received.body_text();
    let boundary = boundary_of(received);

    assert!(
        body.contains(
            "filename=\"a.txt%0D%0AX-Injected: yes%0D%0A%0D%0Aforged%0D%0A--x--%0D%0A\"\r\n"
        ),
        "{body:?}"
    );
    assert!(
        !body.contains("X-Injected: yes\r\n"),
        "CRLF must not have survived into a header line: {body:?}"
    );
    assert_eq!(
        part_count(received, &boundary),
        1,
        "the filename must not have opened a second part: {body:?}"
    );
    assert_eq!(
        body.matches("Content-Disposition:").count(),
        1,
        "exactly one disposition header may exist: {body:?}"
    );
}

#[tokio::test]
async fn crlf_in_a_field_name_cannot_forge_a_header_or_an_extra_part() {
    // The same attack through the other user-controlled slot. `name` and
    // `filename` are escaped by one function; if that ever became two, this
    // pair notices.
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().text("crlf\r\nX-Injected: yes", "value"))
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    let body = received.body_text();

    assert!(
        body.contains("name=\"crlf%0D%0AX-Injected: yes\"\r\n"),
        "{body:?}"
    );
    assert!(
        !body.contains("X-Injected: yes\r\n"),
        "CRLF must not have survived into a header line: {body:?}"
    );
    assert_eq!(body.matches("Content-Disposition:").count(), 1, "{body:?}");
}

#[tokio::test]
async fn a_lone_line_break_is_normalised_in_a_name_and_left_alone_in_a_filename() {
    // Capture section 2 tested only a *paired* CRLF, which comes out as
    // `%0D%0A` from either rule, so it cannot tell the two slots apart. Blink
    // escapes a name with `kNormalizeCRLF` and a filename with
    // `kDoNotNormalizeCRLF` (capture section 5), and those disagree on a lone
    // CR and a lone LF: the name is normalised to a full CRLF first, the
    // filename is not.
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(
            Form::new()
                .text("cr\rhere", "value")
                .text("lf\nhere", "value")
                .part("f", Part::text("x").file_name("cr\rlf\nhere")),
        )
        .send()
        .await
        .expect("the request must succeed");

    let body = server.received()[0].body_text();
    assert!(body.contains("name=\"cr%0D%0Ahere\"\r\n"), "{body:?}");
    assert!(body.contains("name=\"lf%0D%0Ahere\"\r\n"), "{body:?}");
    assert!(body.contains("filename=\"cr%0Dlf%0Ahere\"\r\n"), "{body:?}");
    // Whatever the mapping, no line break may survive as one.
    assert_eq!(body.matches("Content-Disposition:").count(), 3, "{body:?}");
}

#[tokio::test]
async fn a_non_ascii_filename_is_sent_as_raw_utf8_without_a_filename_star() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().part("upload", Part::text("x").file_name("rép\"ort—ünïcode.txt")))
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];

    // Capture section 2, byte for byte: C3 A9 is `é`, E2 80 94 is the em dash,
    // and the quote is the only thing escaped.
    let expected: &[u8] = b"filename=\"r\xc3\xa9p%22ort\xe2\x80\x94\xc3\xbcn\xc3\xafcode.txt\"\r\n";
    assert!(
        received
            .body
            .windows(expected.len())
            .any(|window| window == expected),
        "{:?}",
        received.body_text()
    );
    assert!(
        !received.body_text().contains("filename*"),
        "Chrome never emits an RFC 5987 `filename*`, so neither may this"
    );
}

#[tokio::test]
async fn control_bytes_other_than_the_line_breaks_travel_literally() {
    // Blink's escape has a `default:` arm that pushes the byte, so a NUL or a
    // DEL is not escaped. Pinned because "escape the three that matter" invites
    // a later "and these other suspicious ones too", which would diverge.
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    // Both names carry the same control bytes; only the second also carries a
    // quote. That matters: a name holding none of the three escaped bytes takes
    // the borrowed fast path and never consults the escape table at all, so a
    // table that grew a fourth entry would show up only in the second name.
    client
        .post(server.url_for("example.test", "/"))
        .multipart(
            Form::new()
                .text("a\0b\x01c\x7fd", "v")
                .text("a\0b\x01c\x7fd\"", "v"),
        )
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    for expected in [
        &b"name=\"a\x00b\x01c\x7fd\"\r\n"[..],
        &b"name=\"a\x00b\x01c\x7fd%22\"\r\n"[..],
    ] {
        assert!(
            received
                .body
                .windows(expected.len())
                .any(|window| window == expected),
            "{expected:?} is missing from {:?}",
            received.body_text()
        );
    }
    // They are inert either way: the part count is what a forged header would
    // change, and it does not.
    assert_eq!(part_count(received, &boundary_of(received)), 2);
}

// ------------------------------------------------- length versus chunked

#[tokio::test]
async fn an_escaped_name_keeps_the_declared_length_honest() {
    // The escape changes the header block's length, and the block's length is
    // what `Content-Length` is summed from. A name that escapes to *more* than
    // three bytes per character -- a lone CR widens to `%0D%0A` -- is the case
    // where an encoder that measured before escaping would disagree with the
    // bytes it then wrote.
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    let hostile = "\"\r\n".repeat(2_000);
    client
        .post(server.url_for("example.test", "/"))
        .multipart(
            Form::new()
                .text(hostile.clone(), "v")
                .part("f", Part::text("y").file_name(hostile)),
        )
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    let body = received.body_text();
    assert_eq!(received.header("transfer-encoding"), None);
    assert_eq!(
        received.header("content-length"),
        Some(received.body.len().to_string()).as_deref(),
        "the declared length must match the escaped bytes actually written"
    );
    // That comparison alone proves less than it looks: the server reads exactly
    // `Content-Length` bytes, so an undercount truncates the body and the two
    // numbers agree on the short value. What an undercount cannot fake is the
    // tail, so assert the body is whole -- both escaped names in full, and the
    // closing delimiter present.
    assert!(
        body.ends_with(&format!("--{}--\r\n", boundary_of(received))),
        "an undercounted length would have cut the closing delimiter: {:?}",
        &body[body.len().saturating_sub(80)..]
    );
    let escaped = "%22%0D%0A".repeat(2_000);
    assert!(body.contains(&format!("name=\"{escaped}\"\r\n")), "name");
    assert!(
        body.contains(&format!("filename=\"{escaped}\"\r\n")),
        "filename"
    );
}

#[tokio::test]
async fn a_stream_that_yields_an_empty_chunk_does_not_truncate_a_chunked_body() {
    use futures_util::stream;

    // The in-memory path filters an empty frame out itself; the stream path
    // hands the caller's chunks through untouched and relies on hyper dropping
    // an empty one before it reaches the socket. Under chunked encoding a
    // zero-length chunk *is* the end-of-body marker, so if that reliance ever
    // stops holding, everything after the empty chunk disappears silently.
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    let chunks = vec![
        Ok(Bytes::from_static(b"before")),
        Ok(Bytes::new()),
        Ok(Bytes::from_static(b"after")),
    ];

    client
        .post(server.url_for("example.test", "/"))
        .multipart(
            Form::new()
                .part("upload", Part::stream(stream::iter(chunks)))
                .text("last", "present"),
        )
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    let body = received.body_text();
    assert_eq!(received.header("transfer-encoding"), Some("chunked"));
    assert!(body.contains("\r\n\r\nbeforeafter\r\n--"), "{body:?}");
    assert!(
        body.contains("name=\"last\"\r\n\r\npresent\r\n"),
        "the part after the empty chunk must survive: {body:?}"
    );
    assert_eq!(part_count(received, &boundary_of(received)), 2, "{body:?}");
}

#[tokio::test]
async fn a_form_of_known_size_parts_declares_a_content_length() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(
            Form::new()
                .text("plain", "ordinary")
                .part("upload", Part::bytes(&b"0123456789"[..]).file_name("f.bin")),
        )
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    assert_eq!(
        received.header("content-length"),
        Some(received.body.len().to_string()).as_deref(),
        "the declared length must match the bytes that arrived"
    );
    assert_eq!(received.header("transfer-encoding"), None);
}

#[tokio::test]
async fn a_form_with_a_streaming_part_falls_back_to_chunked() {
    use futures_util::stream;

    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    let chunks = vec![
        Ok(Bytes::from_static(b"one")),
        Ok(Bytes::from_static(b"two")),
    ];

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().text("plain", "ordinary").part(
            "upload",
            Part::stream(stream::iter(chunks)).file_name("f.bin"),
        ))
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    assert_eq!(received.header("content-length"), None);
    assert_eq!(received.header("transfer-encoding"), Some("chunked"));
    assert!(
        received.body_text().contains("\r\n\r\nonetwo\r\n--"),
        "the streamed chunks must land between the header block and the next delimiter: {:?}",
        received.body_text()
    );
}

#[tokio::test]
async fn a_stream_of_declared_length_keeps_the_content_length_computable() {
    use futures_util::stream;

    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    let chunks = vec![
        Ok(Bytes::from_static(b"one")),
        Ok(Bytes::from_static(b"two")),
    ];

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().part(
            "upload",
            Part::stream_with_length(stream::iter(chunks), 6).file_name("f.bin"),
        ))
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    assert_eq!(
        received.header("content-length"),
        Some(received.body.len().to_string()).as_deref()
    );
    assert_eq!(received.header("transfer-encoding"), None);
}

#[tokio::test]
async fn a_file_part_streams_its_contents_and_still_declares_a_length() {
    let dir = std::env::temp_dir().join(format!(
        "chromulate-multipart-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("the temp directory must be creatable");
    let path = dir.join("payload.bin");
    let contents: Vec<u8> = (0u8..=255).cycle().take(70_000).collect();
    std::fs::write(&path, &contents).expect("the file must be writable");

    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().part(
            "upload",
            Part::file(&path).await.expect("the file must open"),
        ))
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    assert_eq!(
        received.header("content-length"),
        Some(received.body.len().to_string()).as_deref(),
        "a file's length is known, so the form's is too"
    );
    assert!(
        received
            .body
            .windows(contents.len())
            .any(|window| window == contents.as_slice()),
        "the file's bytes must arrive unaltered"
    );
    assert!(
        received.body_text().contains("filename=\"payload.bin\""),
        "the file name defaults to the path's last component"
    );
    assert!(
        received
            .body_text()
            .contains("Content-Type: application/octet-stream\r\n"),
        "no MIME database is linked, so the fallback type is used"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn an_empty_part_still_produces_its_headers_and_delimiters() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new().text("empty", "").text("full", "x"))
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    let b = boundary_of(received);
    assert_eq!(
        received.body_text(),
        format!(
            "--{b}\r\n\
             Content-Disposition: form-data; name=\"empty\"\r\n\
             \r\n\
             \r\n\
             --{b}\r\n\
             Content-Disposition: form-data; name=\"full\"\r\n\
             \r\n\
             x\r\n\
             --{b}--\r\n"
        )
    );
}

#[tokio::test]
async fn an_empty_part_in_a_chunked_form_does_not_truncate_the_body() {
    use futures_util::stream;

    // The content-length form above cannot catch this: an empty frame costs
    // nothing there. Under chunked encoding an empty frame is a zero-length
    // chunk, which *is* the end-of-body marker, so everything after the empty
    // field would be silently dropped.
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    let chunks = vec![Ok(Bytes::from_static(b"streamed"))];

    client
        .post(server.url_for("example.test", "/"))
        .multipart(
            Form::new()
                .text("empty", "")
                .part(
                    "upload",
                    Part::stream(stream::iter(chunks)).file_name("f.bin"),
                )
                .text("last", "present"),
        )
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    assert_eq!(received.header("transfer-encoding"), Some("chunked"));
    let body = received.body_text();
    assert!(body.contains("streamed"), "{body:?}");
    assert!(
        body.contains("name=\"last\"\r\n\r\npresent\r\n"),
        "the fields after the empty one must survive: {body:?}"
    );
    assert_eq!(part_count(received, &boundary_of(received)), 3, "{body:?}");
}

#[tokio::test]
async fn an_empty_form_is_just_the_closing_delimiter() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .multipart(Form::new())
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    let b = boundary_of(received);
    assert_eq!(received.body_text(), format!("--{b}--\r\n"));
}

// ------------------------------------------------------------------ errors

#[tokio::test]
async fn a_mime_type_that_is_not_a_header_value_is_a_builder_error() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    let error = client
        .post(server.url_for("example.test", "/"))
        .multipart(
            Form::new().part(
                "upload",
                Part::text("x")
                    .file_name("f.bin")
                    .mime_str("text/plain\r\nX-Injected: yes"),
            ),
        )
        .send()
        .await
        .expect_err("an unrepresentable MIME type must be rejected");

    assert!(matches!(error, Error::Builder(_)), "{error:?}");
    assert!(error.is_user_error());
    assert_eq!(
        server.request_count(),
        0,
        "nothing may reach the network once the form is known to be invalid"
    );
}

// -------------------------------------------------- the paths not changed

#[tokio::test]
async fn an_ordinary_body_is_unaffected_by_the_multipart_feature() {
    // The default path: no multipart anywhere. Compiled with `multipart` on,
    // this is the check that the feature changed nothing for everyone else.
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, "example.test");

    client
        .post(server.url_for("example.test", "/"))
        .header("content-type", "text/plain")
        .body("just bytes")
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    assert_eq!(received.body_text(), "just bytes");
    assert_eq!(received.header("content-type"), Some("text/plain"));
    assert_eq!(received.header("content-length"), Some("10"));
}
