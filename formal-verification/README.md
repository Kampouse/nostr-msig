# Formal Verification

Mathematical proofs of clear-msig core invariants using [Verus](https://github.com/verus-lang/verus).

## Properties Proved

| ID | Property | Statement |
|----|----------|-----------|
| P1 | Bitmap mutual exclusion | `approval_bitmap & cancellation_bitmap == 0` holds after every operation |
| P2 | Threshold/count correspondence | `count_ones(approval_bitmap) >= threshold` implies Approved status |
| P3 | State transition validity | Only valid paths: Active→Approved→Executed, Active→Cancelled |
| P4 | Set/clear symmetry | `set_approval` clears cancel bit, `set_cancellation` clears approval bit |
| P5 | Reset correctness | `reset_votes()` always zeros both bitmaps |
| P6 | Balance conservation | `total_deposited - total_withdrawn == tracked_balance` always |
| P7 | Gas-escrow conservation (v5) | `funded == burned + drained + balance` after every escrow op; overdraft unrepresentable; revoke burns remainder, conservation holds |
| P8 | Method-scope enforcement (v5) | `dispatch(m).is_ok() ⟺ m ∈ methods` for every method; an approve-only agent key can never propose/execute/submit |
| P9 | Nonce-window replay resistance (v5) | a consumed nonce can never be consumed again (mark idempotence); after slide, every past nonce is dead (out of window ⇒ rejected) |

## Prerequisites

The crates.io `verus` crate is a PLACEHOLDER — do not use it. Install a real
binary build from [verus-lang/verus releases](https://github.com/verus-lang/verus/releases)
(macOS arm64 zip is self-contained: verus, z3, vstd). Verified with
`0.2026.08.15.7d4628a`. Note: this Verus generation requires `final(self)` for
postcondition derefs of `&mut self` — the sources here are already migrated.

## Run Verification

```bash
cd formal-verification
verus src/main.rs
```

Expected output:
```
verification results:: 23 verified, 0 errors
```

## Architecture

The proofs extract the core logic from the NEAR contract into a standalone crate:

```
formal-verification/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs    # Verus proof annotations + assertions
```

### Why separate crate?

Verus can't handle `near_sdk` types (AccountId, LookupMap, etc.) directly.
The standard approach is to extract the critical logic and prove it in isolation,
then argue (manually) that the contract code matches the verified model.

### Proof coverage

| Contract module | Lines verified | Method |
|----------------|---------------|--------|
| Bitmap ops | ~30 | Full formal proof |
| State transitions | ~20 | Full formal proof |
| Balance accounting | ~15 | Full formal proof |
| Gas-key escrow (v5) | add_session_key / burn / withdraw / revoke | Full formal proof (P7) |
| Method scoping (v5) | methods allow-list dispatch | Full formal proof (P8) |
| Owner-nonce window (v5) | mark / slide / replay | Full formal proof (P9) |
| Message integrity | — | Covered by proptest (45 tests) |
| Template rendering | — | Covered by proptest (45 tests) |

## Extending the proofs

To add a new property:

1. Write the spec (what should be true):
```rust
spec fn my_invariant(state: &BitmapState) -> bool {
    // mathematical statement
}
```

2. Add proof annotations to the function:
```rust
fn my_operation(&mut self)
    requires self.my_invariant()
    ensures self.my_invariant()
{
    // implementation
}
```

3. Run `verus src/main.rs` — if it passes, the property is mathematically proven.
