//! Manual Phase 2 lookup benchmark at the supported maximum token count.

use rust_panosmcp_auth::{ActorType, ScopeSet, TokenDigest, TokenEntry, TokenStore};
use std::{hint::black_box, time::Instant};

#[test]
#[ignore = "manual benchmark: cargo test -p rust-panosmcp-auth --release --test token_lookup_benchmark -- --ignored --nocapture"]
fn benchmark_maximum_token_store_lookup() {
    let entries = (0..1024)
        .map(|index| TokenEntry {
            name: format!("token-{index:04}"),
            digest: TokenDigest::from_secret(&format!("fixture-secret-{index:04}")),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            created_at: chrono::DateTime::from_timestamp(1, 0).expect("timestamp"),
            expires_at: None,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Unknown,
            oidc_subject: None,
        })
        .collect();
    let store = TokenStore::try_new(entries).expect("maximum supported token store");

    let iterations = 10_000_u32;
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(store.authenticate(black_box("not-a-configured-secret")));
    }
    let elapsed = started.elapsed();
    println!(
        "1024-token miss: {:?} total, {:?}/lookup across {iterations} iterations",
        elapsed,
        elapsed / iterations
    );
}
