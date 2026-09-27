# tierlock

`tierlock` is a small Rust CLI and library for keeping authority anchored while
AI execution moves between device, edge, and cloud zones. It seals a
request-specific execution itinerary with HMAC-SHA256, then verifies the ordered
handoff receipts before a caller trusts the result.

It fails closed on contract tampering, expiry, cross-tenant receipts, stale state
epochs, model or runtime substitution, unapproved zones, broken chains, missing
attestations, latency overruns, and unauthorized actuation.

## Install

Stable Rust 1.85 or newer is required.

```console
cargo install --path .
```

## Quick start

The repository includes a read-only itinerary and a valid two-hop handoff chain.

```console
export TIERLOCK_KEY='replace-with-a-random-secret'

tierlock seal \
  --contract fixtures/itinerary.json \
  --output itinerary.sealed.json

tierlock verify \
  --bundle itinerary.sealed.json \
  --receipts fixtures/handoffs.jsonl \
  --now-ms 1893456000000
```

An allowed chain exits `0` and prints a JSON report:

```json
{
  "itinerary_id": "demo-route-001",
  "decision": "allow",
  "fallback": "safe_stop",
  "receipts_checked": 2,
  "violations": []
}
```

A policy denial exits `2` and reports every detected violation. Invalid input,
I/O failures, and a missing signing key exit `1`. Use `--output report.json` for
machine-oriented pipelines.

## Contract boundary

`tierlock` verifies an itinerary and receipt chain; it does not perform remote
attestation, schedule workloads, store keys, or actuate a system. HMAC is a
shared-secret mechanism, so producers and verifiers are equally trusted. Put the
key in a secret manager in real deployments and rotate it outside this tool.

The JSON contract binds:

- tenant, workload, itinerary, nonce, and monotonic state epoch;
- model and runtime SHA-256 digests;
- allowed trust zones and whether attestation receipts are mandatory;
- cumulative latency budget and absolute expiry;
- read-only versus actuation authority and the required fallback.

Each JSONL receipt repeats the bound identity and digests, names the handoff
zones, records cumulative latency and observation time, and declares the action
observed. Chaining requires each `from_zone` to equal the previous `to_zone`.

## Rust library

The public `seal` and `verify` functions accept typed `Itinerary`,
`SealedItinerary`, and `HandoffReceipt` values. Verification returns a structured
`VerificationReport`; it does not terminate the process or perform I/O.

## Development

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The crate forbids unsafe Rust. CI repeats all three checks on every push and pull
request.

## License

MIT
