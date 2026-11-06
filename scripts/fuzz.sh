#!/usr/bin/env bash
# All fuzz targets in parallel for N s (default 600).
# Requires: rustup toolchain install nightly; cargo install cargo-fuzz
# Crashes -> fuzz/artifacts/<target>/; growing corpus -> fuzz/corpus/<target>/.
set -euo pipefail
cd "$(dirname "$0")/../fuzz"
secs="${1:-600}"
targets=(cwmp_decode usp_record dm_path mqtt_packet xmpp_stream)
cargo +nightly fuzz build --target x86_64-unknown-linux-gnu
for t in "${targets[@]}"; do
  mkdir -p "corpus/$t"
  cargo +nightly fuzz run --target x86_64-unknown-linux-gnu "$t" "corpus/$t" "seeds/$t" \
    -- -max_total_time="$secs" -max_len=8192 >"$t.log" 2>&1 &
done
fail=0
for job in $(jobs -p); do wait "$job" || fail=1; done
for t in "${targets[@]}"; do grep -E "^Done|SUMMARY" "$t.log" | sed "s/^/$t: /"; done
exit "$fail"
