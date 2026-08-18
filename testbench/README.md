# nostr-msig v4 — Testbench

One-command testnet verification of the nostr-msig v4 contract
(noauth msig + NEP-611 session/gas keys).

## What it does

`node run.js` will, end to end:

1. **Build** the contract wasm (rust 1.95 + `wasm-opt`) — or reuse one
2. **Create** a fresh funded subaccount `bench<rand>.<signer>`
3. **Deploy** the wasm + `new([owner_npub])`
4. **Verify** the full v4 surface:
   - wallet creation, AddIntent propose/approve/execute (nostr schnorr sigs)
   - deposit flow
   - `add_session_key` → gas keys visible on-chain (`GasKeyFunctionCall`)
   - `session_ping` signed **as** the gas key (TransactionV1)
   - **relayer-free `submit_action`** quick transfer 0.1Ⓝ (balance deltas asserted)
   - auth rejections: wrong wallet, non-session signer, expired key
   - `refresh_session` top-up, `revoke_session` → keys vanish

Total cost: ~8.7Ⓝ (≈6.4Ⓝ one-time contract storage + ~2Ⓝ ops/gas-key funding
+ fees). Verified working: full run on `bench5wsu.vault.kampy.testnet`
(23 checks green, incl. relayer-free 0.1Ⓝ transfer with asserted balance
deltas).

> **Signer account gotcha:** use a *plain* account as `BENCH_SIGNER` (no
> deployed contract). Contract accounts keep a storage stake locked — e.g.
> `nmsig.vault.kampy.testnet` (6.8Ⓝ stake) can only send `balance − stake`.
> near-cli-rs refuses with *"doesn't have enough balance … after
> transaction"* when a transfer would breach it.

## Prereqs

- node ≥ 18
- **near-cli-rs ≥ 0.30** (`cargo install near-cli-rs`) — needed to sign
  TransactionV1 gas-key txs. Default path `~/.cargo/bin/near`, override with `NEAR_BIN`.
- rust 1.95.0 toolchain (only if building: `rustup toolchain install 1.95.0`)

## Quick start

```bash
cd testbench
npm install
node run.js
```

Defaults: signer `vault.kampy.testnet`, fund 9Ⓝ, throwaway bench owner key
(derived from passphrase `nostr-msig-bench-v1`).

## What a clean run looks like

```
━━━ creating benchXXX.vault.kampy.testnet ━━━
✅ created benchXXX… (tx …)
━━━ deploying ━━━
✅ on-chain code hash matches (bd4040bf…)
✅ init OK — version 4
━━━ running full verification bench ━━━
✅ create_wallet / propose / approve / execute (Deposit + Transfer intents)
✅ add_session_key main + short → GasKeyFunctionCall visible on-chain
✅ session_ping via gas key (TransactionV1)  → pong:…
✅ submit_action quick Transfer 0.1Ⓝ via gas key
🛡️  wrong wallet / non-session signer / expired key → rejected
✅ refresh_session / revoke_session ×2 → keys vanish
╔══ RESULT ════ ALL PASS ✅  23 checks green
```

Takes ~4–5 minutes (one 32s wait for the short session key to expire).

## Using your real nostr key as owner

```bash
node run.js  # with any of:
BENCH_OWNER_NSEC=nsec1… node run.js          # your nsec
BENCH_OWNER_SECRET=<64-hex> node run.js      # raw hex secret
BENCH_OWNER_PASSPHRASE="my secret" node run.js
```

The owner key never leaves your machine — it's only used to schnorr-sign
proposal messages locally.

## Useful env vars

| var | default | meaning |
|---|---|---|
| `BENCH_SIGNER` | `vault.kampy.testnet` | funded account that creates the bench subaccount (key must be in `~/.near-credentials/testnet/`) |
| `BENCH_FUND` | `8` | NEAR sent to the bench account |
| `BENCH_NAME` | `bench<rand>` | subaccount name |
| `SKIP_BUILD` / `BENCH_WASM` | — | skip cargo, reuse a wasm |
| `BENCH_RECIPIENT` | signer | who receives the test 0.1Ⓝ transfer |
| `NEAR_BIN` | `~/.cargo/bin/near` | near-cli-rs path |

## Re-run on the same bench account

```bash
BENCH_CONTRACT=bench123.vault.kampy.testnet node bench.cjs   # new wallet each run
```

`bench.cjs` is resumable-ish: each run uses a fresh wallet name, so a failed
run doesn't poison the next.

## Tear down

```bash
node cleanup.js bench123.vault.kampy.testnet vault.kampy.testnet
```

Deletes the bench account and refunds the remaining balance.

## v5 — widened session-key methods + drain-then-revoke

`add_session_key` takes optional `methods: Vec<String>` (allowlist:
submit_action, session_ping, propose, approve, execute, amend,
cancel_vote). Omit it for the v4 default (submit_action,session_ping).
Governance methods still verify their own nostr sigs — the key only
pays postage, so widening never widens authority.

Proven live on `benchv5.vault.kampy.testnet` (finish.cjs):
- propose → agent-npub approve → execute, all as **pure-JS V1 gas-key txs**
- agent key scoped to [approve, session_ping] enforced by the protocol
- WithdrawFromGasKey drain → revoke with 0 burned

Key ops gotchas learned the hard way:
- gas keys can't be deleted while balance > 1Ⓝ (NEP-611 guard) — drain first
- `delete_wallet` refunds storage only, not the wallet's internal ledger
- proposals expire (~1h default) — benches must propose fresh, not resume stale ones
- fat contract accounts can't be deleted in one tx (DeleteAccountWithLargeState)
- near-cli-rs exit codes lie on transient RPC errors — verify by polling state
