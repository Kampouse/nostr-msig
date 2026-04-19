#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "Building WASM..."
cargo build --release --target wasm32-unknown-unknown

INPUT="target/wasm32-unknown-unknown/release/clear_msig.wasm"
OUTPUT="target/clear_msig.wasm"

echo "Optimizing with wasm-opt..."
wasm-opt -Oz --strip-debug --strip-producers --dce "$INPUT" -o "$OUTPUT"

SIZE=$(ls -lh "$OUTPUT" | awk '{print $5}')
echo "✅ Built: $OUTPUT ($SIZE)"
