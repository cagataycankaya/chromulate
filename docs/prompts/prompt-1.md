You are the lead architect and Principal Rust Engineer for a new open-source project.
 
Your job is to design a production-grade Rust networking library from scratch.
 
The project name is currently:
 
Chromulate
 
\## Vision
 
Chromulate is NOT another HTTP client.
 
Chromulate is a browser-grade networking engine that accurately emulates modern Chrome network behavior without embedding Chromium.
 
It is designed for:
 
\- Web scraping
 
\- Web crawling
 
\- Search indexing
 
\- Monitoring
 
\- Security research
 
\- Automation
 
The goal is to achieve browser-level network compatibility while maintaining the performance and memory footprint of a native Rust HTTP client.
 
Think of it as:
 
"Hyper + Browser Networking"
 
NOT:
 
"Playwright"
 
There will be:
 
\- no JavaScript engine
 
\- no Blink
 
\- no DOM
 
\- no HTML renderer
 
\- no Chromium
 
\- no V8
 
The project only focuses on the networking layer.
 
\--------------------------------------------------
 
\## Main Goals
 
Design a networking engine capable of producing requests that closely match Chrome's network behavior.
 
The project should be:
 
\- async-first
 
\- Tokio based
 
\- zero-copy whenever possible
 
\- extremely low memory usage
 
\- high throughput
 
\- modular
 
\- production ready
 
\--------------------------------------------------
 
\## Core Features
 
Design every subsystem.
 
\### Browser Profiles
 
Support profiles like
 
\- Chrome Stable
 
\- Chrome Beta
 
\- Chrome Canary
 
Each profile automatically configures:
 
\- TLS behavior
 
\- HTTP headers
 
\- HTTP/2 behavior
 
\- Client Hints
 
\- Compression
 
\- Accept-Language
 
\- User-Agent
 
\--------------------------------------------------
 
\### TLS Engine
 
Design a TLS subsystem capable of reproducing Chrome-like TLS behavior.
 
Include architecture for:
 
\- ClientHello generation
 
\- Cipher ordering
 
\- Extensions ordering
 
\- ALPN
 
\- GREASE
 
\- KeyShare
 
\- Session Tickets
 
\- TLS 1.3
 
\--------------------------------------------------
 
\### HTTP Engine
 
Support
 
GET
 
POST
 
PUT
 
PATCH
 
DELETE
 
Multipart
 
Streaming
 
Downloads
 
Uploads
 
\--------------------------------------------------
 
\### HTTP/2 Engine
 
Design a browser-compatible implementation.
 
Include:
 
\- SETTINGS
 
\- PRIORITY
 
\- WINDOW\_UPDATE
 
\- HPACK
 
\- Stream lifecycle
 
\- Header ordering
 
\--------------------------------------------------
 
\### HTTP/3
 
Design architecture only.
 
Implementation later.
 
\--------------------------------------------------
 
\### Cookie Engine
 
Browser-grade cookie management.
 
\--------------------------------------------------
 
\### Session Manager
 
Persistent browser sessions.
 
Connection reuse.
 
\--------------------------------------------------
 
\### Proxy Engine
 
Support
 
HTTP
 
HTTPS
 
SOCKS5
 
Authentication
 
Rotation
 
\--------------------------------------------------
 
\### DNS
 
Support custom resolvers.
 
Future support:
 
DoH
 
DoT
 
\--------------------------------------------------
 
\### Compression
 
gzip
 
brotli
 
zstd
 
\--------------------------------------------------
 
\### Middleware
 
Tower-inspired middleware architecture.
 
\--------------------------------------------------
 
\### Retry
 
Retry policies.
 
\--------------------------------------------------
 
\### Rate Limiter
 
Token bucket.
 
\--------------------------------------------------
 
\### Metrics
 
OpenTelemetry.
 
\--------------------------------------------------
 
\### Logging
 
Tracing crate.
 
\--------------------------------------------------
 
\## Public API
 
The API should be extremely ergonomic.
 
Example:
 
\`\`\`rust
 
let client = Client::chrome();
 
let response = client
 
.get("[https://example.com](https://example.com) ")
 
.send()
 
.await?;
 
\`\`\`
 
Builder:
 
\`\`\`rust
 
let client = Client::builder()
 
.profile(Profile::ChromeStable)
 
.cookie\_store(true)
 
.build()?;
 
\`\`\`
 
\--------------------------------------------------
 
\## Workspace Layout
 
Design a Cargo workspace.
 
Explain responsibilities of every crate.
 
Example:
 
chromulate-core
 
chromulate-http
 
chromulate-tls
 
chromulate-http2
 
chromulate-http3
 
chromulate-profile
 
chromulate-cookie
 
chromulate-session
 
chromulate-proxy
 
chromulate-dns
 
chromulate-compression
 
chromulate-cache
 
chromulate-auth
 
chromulate-middleware
 
chromulate-metrics
 
chromulate-cli
 
Explain why each crate exists.
 
\--------------------------------------------------
 
\## Traits
 
Design trait hierarchy.
 
Avoid unnecessary abstraction.
 
Favor zero-cost abstractions.
 
\--------------------------------------------------
 
\## Performance
 
Target:
 
Very low allocations
 
Minimal Arc usage
 
Avoid unnecessary Mutex
 
Use Bytes where appropriate
 
Streaming everywhere possible
 
Efficient connection pooling
 
SIMD where beneficial
 
\--------------------------------------------------
 
\## Error Handling
 
Design a unified error system.
 
\--------------------------------------------------
 
\## Testing
 
Design:
 
Unit tests
 
Integration tests
 
Compatibility tests
 
Regression tests
 
Benchmarks
 
\--------------------------------------------------
 
\## CI/CD
 
Design GitHub Actions.
 
Linting
 
Formatting
 
Miri
 
Clippy
 
cargo-nextest
 
Coverage
 
\--------------------------------------------------
 
\## Documentation
 
Design
 
Book
 
Examples
 
Cookbook
 
Architecture docs
 
API docs
 
\--------------------------------------------------
 
\## Roadmap
 
Create a roadmap.
 
Phase 1
 
Core HTTP client
 
Phase 2
 
TLS engine
 
Phase 3
 
Browser profiles
 
Phase 4
 
HTTP/2 compatibility
 
Phase 5
 
HTTP/3
 
Phase 6
 
Performance optimization
 
\--------------------------------------------------
 
\## Important
 
This project is NOT intended to bypass security systems.
 
Its purpose is to faithfully reproduce standards-compliant browser networking behavior while remaining lightweight and high-performance.
 
Do not write implementation code.
 
Instead, produce a complete engineering architecture document suitable for a team of senior Rust engineers beginning implementation.