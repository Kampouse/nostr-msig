# Version History — deep detail

Front-page summary lives in the [README](../README.md). This file keeps the full engineering detail for each release line.

## v3 Security Upgrade

v3 hardens the owner (nostr) signature path. The unit tests (`cd contract && cargo test`) and the on-chain e2e (`node e2e-v3.cjs`) both pass green.

### Multi-owner npub set

`new(owner_npubs: Vec<String>)` initializes a **set** of owner npubs (32-byte x-only pubkey, hex-encoded). Any owner key can authorize owner actions; owners can be added/removed via signed `add_owner_npub` / `remove_owner_npub` calls. The signing keys are BIP-340 schnorr keys — same curve/format as Nostr (the client signs `sha256(message)` with a secp256k1 schnorr key).

### Guardian pause

An optional **guardian npub** (`set_guardian`) may pause the contract (`pause`), blocking every state-changing call except `unpause`. The guardian can **only** pause — it cannot move funds or change config. Pause/unpause are clear-signed:

```
expires {expires_at}.000000000: pause | contract: {account_id}
```

### Anti-replay: contract-id binding + nonce window

Every signed message now ends with `| contract: {account_id}`, so a signature for one deployment is useless on another contract (or another chain). Owner-action messages additionally carry a client-chosen nonce:

```
expires {expires_at}.000000000: {action} | nonce: {nonce} | contract: {account_id}
```

- Owner nonces use a **64-slot sliding window**: any *unused* nonce in `[get_owner_nonce(), get_owner_nonce()+64)` is accepted. Consumed nonces are tracked in a bitmap; the window base slides forward only across contiguous consumed nonces, so gaps intentionally pin the base (skipped low nonces remain usable later).
- Replaying a used nonce → `ERR_NONCE_ALREADY_USED`; a nonce outside the window → `ERR_NONCE_WINDOW_EXCEEDED`.
- Failed receipts revert nonce consumption (NEAR rollback), so a rejected tx never burns a nonce. Clients should use mostly-contiguous nonces to keep the window moving.
- Proposal-flow messages are bound per-proposal instead (proposal index + expiry + contract id) — no nonce needed for `approve`.

### Relayer payout

Each wallet can set a `relayer_fee` (and optional relayer allowlist). On execution, if the transaction submitter is an allowed relayer (and not the contract itself), the fee is paid out of the wallet's NEAR balance — rewarding gas-paying relayers.

### Client message formats (must match exactly)

Owner actions (create_wallet, set_guardian, set_relayer_fee, propose, execute, unpause, …):
```
expires {expires_at}.000000000: {action} | nonce: {nonce} | contract: {account_id}
```

Proposals (via `get_proposal_message` / `build_message`):
```
expires {expires_at}.000000000: {action} {content} | wallet: {wallet} proposal: {idx} | contract: {account_id}
```

Proposal content: transfers → `transfer {amount} to {recipient}`; add-intent → `add intent definition_hash: {sha256_hex_of_intent_json}`; deposit → `deposit NEAR to wallet`.

Use whole-second expiry — `(floor(now/1000)+7200)*1e9` as a NUMBER — so the `u64` survives the JSON double round-trip exactly.

Signing (JS): `schnorr.sign(sha256(new TextEncoder().encode(msg)), nsec)` with `@noble/curves` secp256k1. Note noble v1.x `verify()` argument order is `(signature, message, pubkey)` — signature first.

### End-to-end test

```bash
node e2e-v3.cjs          # full flow on nmsig.vault.kampy.testnet
START=4 node e2e-v3.cjs  # resume from step 4 (skips the first 4 steps)
```

Covers: multi-owner init, wallet creation, AddIntent(Deposit/Transfer) propose→approve→execute, deposits, 0.5Ⓝ transfer, replay-nonce rejection, out-of-window nonce rejection, guardian pause/unpause, and relayer fee config.

### ⚠️ near CLI artifact-cache gotcha

`near-cli-rs` (v2m0) caches compiled wasm at `~/.near-cli/artifacts/<account>.wasm` and can **silently deploy stale wasm** with `near contract deploy use-file`. Always verify the on-chain `code_hash` against your local file's sha256 after deploying. `deploy2.cjs` does this:

```bash
node deploy2.cjs <account-id> <path/to/contract.wasm>
# writes result (incl. hash match) to /tmp/deploy_result.txt
```

## v4 Session Keys (NEP-611 Gas Keys)

v4 added **relayer-free session keys**: a client-held ed25519 key that can submit pre-authorized actions to a wallet **without a relayer paying gas**, implemented with [NEP-611 gas keys](https://github.com/near/NEPs/pull/611). Requires protocol ≥85 (testnet/mainnet current) and near-sdk 5.29. Unit tests (`cd contract && cargo test` — toolchain pinned to 1.95.0 in `contract/rust-toolchain.toml`, 22 green incl. all v3/v4/BIP-340/migrate-guard tests) and the on-chain e2e (`node e2e-v4.cjs`) both pass green. v5 extends them with method scoping and agent delegation.

### How NEP-611 gas keys work

A gas key is an access key on the **contract account** whose transactions are paid from a **prepaid balance attached to the key itself** instead of the account's balance:

- `GasKeyFunctionCall { balance, num_nonces, allowance: None, receiver_id, method_names }` — balance is the gas budget; `allowance` must be `None`/unlimited (protocol requirement: prepaid balance *is* the budget), `receiver_id` is the contract, `method_names` is `["submit_action", "session_ping"]`.
- Gas-key transactions use **TransactionV1** with a `GasKeyNonce { nonce, nonce_index }` — up to `num_nonces` (1..=1024) parallel lanes per key, each with its own nonce sequence.
- **Deletion burns the remaining balance, max 1 NEAR** — so the contract caps lifetime funding at **1 Ⓝ per key** and clients should top up in small increments (`refresh_session`). To recover balance before revoking, the key owner can withdraw on-chain first via CLI (`near account withdraw-from-gas-key …`); the contract itself cannot read a key's balance, so it cannot sweep on revoke.
- Gas refunds flow back to the gas key's balance.

### Methods (v4)

| Method | Who signs | What it does |
|---|---|---|
| `add_session_key(public_key, num_nonces, expires_at, wallet, label, initial_gas, nonce, expires_at_sig, signature)` | owner nostr | Registers the session meta and creates the gas key via promise batch: `add_gas_key_allowance_function_call` (Allowance::Unlimited, methods `submit_action,session_ping`) chained with `transfer_to_gas_key(initial_gas)`. `num_nonces` clamped to 1..=1024, `expires_at` clamped to now+30d, `initial_gas` capped so lifetime funding ≤ 1 Ⓝ. Wallet internal balance is debited. |
| `refresh_session(public_key, amount, nonce, expires_at_sig, signature)` | owner nostr | Top-up via `transfer_to_gas_key` from the wallet's internal balance (same ≤1 Ⓝ lifetime cap). |
| `revoke_session(public_key, nonce, expires_at_sig, signature)` | owner nostr | Removes meta + `Promise::delete_key` (remaining balance burns per NEP-611; see above), emits `session_key_revoked`. |
| `submit_action(action, wallet_name, intent_index, proposal_id, param_values, expires_at, nonce, signature)` | **session key** (gas-key tx) + owner nostr sig in args | Session-key entry point. `env::signer_account_pk()` must equal a registered, unexpired session key bound to `wallet_name`; contract must not be paused. The inner action (`quick`/`propose`/`amend`/`execute`/`cancel`) is verified exactly like the v3 relayer paths — the owner still nostr-signs every action. No attached deposit. |
| `session_ping()` | session key | No-op liveness check, returns `pong:{wallet}:{pubkey_prefix}`. |
| `list_sessions(wallet)` / `get_session(public_key)` / `get_session_count()` | view | Session metadata. |

State: `sessions: UnorderedSet<SessionMeta>` + `LookupMap<pubkey, SessionMeta>` with `{public_key, wallet, created_at, expires_at, funded_yocto, label}`. NEP-297 events: `session_key_added` / `session_key_refreshed` / `session_key_revoked`. Deploying v4 over v3 state requires one `migrate()` call (`#[init(ignore_state)]`, reads `ContractV3` state).

### v4 message formats (owner nostr signatures)

Same shape as v3 — `expires {sig_expiry}.000000000: {action} | nonce: {n} | contract: {account_id}`, BIP-340 schnorr over `sha256(message)`:

- `add_session_key:{public_key_hex_64}` (full hex, no `ed25519:` prefix)
- `refresh_session:{public_key_hex_64}:{amount_yocto}`
- `revoke_session:{public_key_hex_64}`
- submit_action inner actions identical to v3 relayer paths (e.g. `quick:{wallet}:{intent_index}:{param_values_first_64_chars}`)

Nonce rules unchanged: client-chosen in `[get_owner_nonce(), +64)` sliding window; failed receipts revert nonce consumption.

### Client notes

- **near-api-js ≤0.44 cannot sign gas-key transactions** (no `TransactionV1`/`GasKeyNonce` support — fails with `InvalidNonceIndex`). Use **near-cli-rs ≥0.30**, which auto-detects gas keys, picks `nonce_index`, and builds TransactionV1:

```bash
near contract call-function as-transaction nmsig.vault.kampy.testnet submit_action \
  json-args '{"action":"quick",...}' prepaid-gas '50 Tgas' attached-deposit '0 NEAR' \
  sign-as nmsig.vault.kampy.testnet network-config testnet \
  sign-with-plaintext-private-key ed25519:… send
```

- Chains supporting protocol ≥85 (testnet & mainnet today) accept gas keys; older chains reject TransactionV1.
- Session keys only pay for gas — the owner nostr signature still gates every action, pause blocks sessions too, and a session is hard-bound to one wallet (`ERR_SESSION_WALLET_MISMATCH` otherwise).
- RPC quirk: `view_access_key` takes the **base58** (`ed25519:…`) form of the key, while contract args use raw 64-hex.

### Tier-1 security hardening (Aug 21, 2026)

**migrate() access guard.** `migrate()` was callable by anyone with no state-version check. On the live v5 state the borsh trailing-bytes mismatch makes re-migration fail, but any future prefix-compatible layout would have let a griefer re-run it and silently **wipe all registered session keys** (state rebuilt from the v3 subset, empty session registries). Fixed with a strict one-shot guard:

- `assert_eq!(old.version, 3, "ERR_NOT_V3_STATE")` — migration only ever fires on genuine v3 state
- Covered by 3 unit tests: legit v3→v5 migration (state carried, sessions empty), re-migration against v5 state panics, and a forced prefix-compatible v4/v5-shaped state is rejected by the version assert

**BIP-340 conformance.** All 19 official test vectors from [bip-0340/test-vectors.csv](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv) (incl. the 2022-12 variable-length additions) pass through the exact on-chain verify primitive (`k256::schnorr::VerifyingKey::verify_raw` — the call `try_schnorr_verify` makes after the nostr-style `sha256(clear_sign_text)` pre-hash). Edge cases covered: pubkey not on curve, pubkey x ≥ field size, R.y odd, negated message/s, s ≥ curve order, sG−eP = infinity, non-curve R.x, msg ≥ p unreduced. Also verified: secret-key→x-only-pubkey derivation matches the vectors (nostr wallet compatibility), and the contract's manual `sha256 → verify_raw` path is byte-identical to k256's own `Verifier::verify`.

**Build hygiene.** `contract/rust-toolchain.toml` was stale at 1.86 (April-era, near-sdk 5.9); the locked deps require ≥1.93 — pinned to 1.95.0. Removed a duplicate `use super::*` in `message.rs`.
