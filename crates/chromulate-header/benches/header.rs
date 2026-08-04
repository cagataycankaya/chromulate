//! Building the ordered header list, which happens once per request.
//!
//! Two shapes are measured because they take different amounts of work: a
//! top-level navigation, which carries `Sec-Fetch-User`, an `Accept` for a
//! document and the full client-hint set; and a cross-origin subresource fetch,
//! which carries an `Origin` header and a computed `Sec-Fetch-Site`. The
//! third case exercises the granted high-entropy client hints, which add
//! headers the first two do not send.
//!
//! Run with `cargo bench -p chromulate-header`.

use std::hint::black_box;
use std::sync::Arc;

use chromulate_core::{
    Body, FetchDest, FetchMode, Origin, Request, RequestOptions, reexport::Method,
};
use chromulate_header::{AcceptChStore, HeaderEngine, UserActivatedNavigation};
use chromulate_profile::Profile;
use criterion::{Criterion, criterion_group, criterion_main};
use url::Url;

fn request(method: Method, activated: bool) -> Request {
    let mut request = Request::new(Body::empty());
    *request.method_mut() = method;
    if activated {
        request.extensions_mut().insert(UserActivatedNavigation);
    }
    request
}

fn benches(c: &mut Criterion) {
    let engine = HeaderEngine::new(Arc::new(Profile::chrome_stable()));
    let empty_store = AcceptChStore::new();

    let page = Url::parse("https://example.com/index.html").expect("a valid URL");
    let asset = Url::parse("https://cdn.example.net/static/app.js").expect("a valid URL");

    let navigation = {
        let mut options = RequestOptions::navigation();
        options.referrer = Some(page.clone());
        options
    };

    let subresource = {
        let mut options = RequestOptions::api();
        options.mode = FetchMode::Cors;
        options.dest = FetchDest::Script;
        options.initiator = Some(Origin::of(&page).expect("a valid origin"));
        options.referrer = Some(page.clone());
        options
    };

    let granted_store = {
        let mut store = AcceptChStore::new();
        store.record(
            Origin::of(&page).expect("a valid origin"),
            "sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-model, \
             sec-ch-ua-platform-version, sec-ch-ua-full-version-list",
        );
        store
    };

    let mut group = c.benchmark_group("header");

    group.bench_function("navigation", |b| {
        b.iter(|| {
            let mut request = request(Method::GET, true);
            let list = engine
                .apply(
                    &mut request,
                    black_box(&page),
                    black_box(&navigation),
                    &empty_store,
                )
                .expect("the shipped profile must produce valid headers");
            black_box(list)
        });
    });

    group.bench_function("subresource_cors", |b| {
        b.iter(|| {
            let mut request = request(Method::GET, false);
            let list = engine
                .apply(
                    &mut request,
                    black_box(&asset),
                    black_box(&subresource),
                    &empty_store,
                )
                .expect("the shipped profile must produce valid headers");
            black_box(list)
        });
    });

    group.bench_function("navigation_with_granted_hints", |b| {
        b.iter(|| {
            let mut request = request(Method::GET, true);
            let list = engine
                .apply(
                    &mut request,
                    black_box(&page),
                    black_box(&navigation),
                    &granted_store,
                )
                .expect("the shipped profile must produce valid headers");
            black_box(list)
        });
    });

    group.finish();
}

criterion_group! {
    name = header;
    config = Criterion::default().sample_size(200);
    targets = benches
}
criterion_main!(header);
