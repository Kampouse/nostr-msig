# nostr-msig

**Clear-signing multisig for NEAR Protocol — with agent delegation (v5).**

> **Note:** This is a NEAR Protocol port of [ChewingGlass/clear-msig](https://github.com/ChewingGlass/clear-msig), the original clear-sign multisig built for Solana using [Quasar](https://github.com/blueshift-gg/quasar).

Signers see exactly what they're approving — human-readable messages, not opaque transaction bytes.

## How It Works

Traditional multisigs have signers approve hashes of serialized transactions. **clear-msig** fixes this:

1. **Intents** define what operations a wallet can perform (transfer NEAR, transfer FTs, deposit, custom actions)
2. **Proposals** fill in the parameters and generate a human-readable message
3. **Signers** read the message, then sign it with their nostr key (BIP-340 schnorr — see below)
4. **Execution** happens only when enough approvals are collected (after timelock)

### Message Format

```
expires <timestamp>: <action> <content> | wallet: <name> proposal: <index> | contract: <account_id>
```

Example:
```
expires 1893456000.000000000: propose transfer 1000000000000000000000000 yoctoNEAR to bob.near | wallet: treasury proposal: 0 | contract: msig.example.testnet
```

No ambiguity. Signers know exactly what they're approving.

## The Nostr Angle

Why is this called **nostr**-msig? Because every authority in the system — owners, guardians, and agents — is a **nostr identity** (an `npub`, a BIP-340 x-only public key):

- **You sign with your nostr key.** The message is a plain string; the signature is BIP-340 schnorr over `sha256(message)` — the exact key format and signing scheme used by every nostr client (Damus, Primal, Amethyst…). If you already have a nostr key pair, you already have a signer key for this contract.
- **Nostr identities, not NEAR accounts, hold authority.** Owners are npubs, the guardian is an npub, and v5 agents are *independent nostr identities* — a second npub that can approve proposals within its scope without ever holding a NEAR full-access key.
- **Nostr *keys*, not the nostr *network*.** The contract never talks to relays. It verifies schnorr signatures on-chain, same as it would verify any signature. No relay dependency, no event kinds — just the key format, because it's a well-tooled, human-ownable identity standard.

The practical payoff: key management, backup, and identity portability come from the nostr ecosystem instead of a bespoke scheme. A nostr hardware key manager or nsec bunker can be the custodian of a treasury signer, and any future nostr tooling that can sign a message can operate this multisig.

## v5 Agent Delegation (Current)

v5 is the flagship: **scoped agent keys that act autonomously on a wallet** — propose, approve, and execute via their own self-funded gas keys, no relayer, no full-access key ever granted. Proven live on testnet (Aug 2026): propose → agent-npub approve (a second, independent nostr identity) → execute, all via pure-JS TransactionV1 gas-key transactions; 0.02Ⓝ moved exactly; out-of-scope agent execute rejected at protocol level; drain + revoke swept all 13 gas keys with 0.249Ⓝ recovered and zero keys left on the account.

### Method-scoped session keys

`add_session_key` now accepts a `methods` parameter — the gas key is scoped to a subset of `["submit_action", "session_ping", "propose", "approve", "execute", "amend", "cancel_vote"]` at the **protocol level** (enforced in `SESSION_KEY_ALLOWED_METHODS` dispatch). Crucially, widening the *transport* scope never widens *authority*: governance methods (`propose`/`approve`/`execute`/…) still verify their own nostr signatures internally. The gas key only pays postage — the npub signature still gates every action.

Typical v5 setup:
- **Owner key**: scoped to `[submit_action, session_ping, propose, approve, execute]`
- **Agent key**: scoped to `[approve, session_ping]` — it can co-sign approvals on its own gas budget, nothing else

### The agent flow (proven on-chain)

1. Owner proposes a transfer (e.g. `AgentTransfer` intent where the agent npub is an approver)
2. **The agent approves via its own scoped gas key** — TransactionV1, self-funded, no owner signature on the transaction
3. Owner (or a delegated key) executes → funds move
4. Any attempt to call a method outside the key's scope is rejected by the runtime before contract logic even runs
5. Cleanup: drain the gas-key escrow back to the wallet ledger, then revoke — remaining balance burns, keys vanish

Guardrails (all on-chain): wallet ledger debited for key funding, minimum wallet reserve enforced, lifetime gas-key funding capped (≤1Ⓝ per key), pause blocks sessions too, sessions hard-bound to one wallet.

### Formal verification

The core invariants are machine-verified with [Verus](https://github.com/verus-lang/verus) — **23 properties proved, 0 errors**. Highlights:

| ID | Property |
|----|----------|
| P7 | Gas-escrow conservation: `funded == burned + drained + balance` after every escrow op; overdraft unrepresentable |
| P8 | Method-scope enforcement: `dispatch(m).is_ok() ⟺ m ∈ methods` — an approve-only agent key can never propose/execute/submit |
| P9 | Nonce-window replay resistance: consumed nonces can never be consumed again; past nonces die when the window slides |

(Plus P1–P6: approval/cancellation bitmap mutual exclusion, threshold correspondence, state-transition validity, vote reset correctness, and balance conservation.) See `formal-verification/README.md` for the full table and how to re-run the proofs.

### Verdicts

The testbench harness (`testbench/`) writes machine-checkable verdict files per run: `v5-final-verdict.json` (flagship flow ok) and `cleanup-verdict.json` (drain + revoke PASS, `gasKeysLeft: 0`). One command re-verifies the whole surface end-to-end on testnet — see `testbench/README.md`.

### Consumer-mode UI mockup

`testbench/mockup.png` — the v5 guardrails rendered as plain English: a proposals inbox, key cards with scope chips + gas gauges, a zero-full-access banner, and an agent kill-switch over the live event feed.

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

v4 adds **relayer-free session keys**: a client-held ed25519 key that can submit pre-authorized actions to a wallet **without a relayer paying gas**, implemented with [NEP-611 gas keys](https://github.com/near/NEPs/pull/611). Requires protocol ≥85 (testnet/mainnet current) and near-sdk 5.29. Unit tests (`cd contract && cargo +1.95.0 test`, 16 green incl. all 11 v3 tests) and the on-chain e2e (`node e2e-v4.cjs`) both pass green.

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

## Features

| Feature | Description |
|---------|-------------|
| Clear-signing | Human-readable messages signed with ed25519 |
| Intent-based governance | Define allowed operations, proposers, approvers, thresholds |
| Meta-intents | Self-governance: AddIntent, RemoveIntent, UpdateIntent |
| Proposal lifecycle | Propose → Amend → Approve → Execute (with timelock) |
| NEP-141 FT support | Receive, hold, and transfer fungible tokens |
| Token allowlists | Per-wallet FT allowlist to prevent griefing |
| Balance tracking | Internal accounting for NEAR and FT balances per wallet |
| Delegation | Approvers can delegate their vote to another account |
| Ownership transfer | Owner can transfer wallet ownership (meta-intents updated) |
| Proposal amendment | Proposer can amend active proposals (resets votes) |
| Wallet deletion | Owner can delete wallet, storage deposit refunded |
| Event nonces | Monotonic counter for strict event ordering |
| Configurable gas | Per-intent execution gas (default 50, max 300 Tgas) |
| Storage accounting | Tracks actual bytes, accurate refunds |
| Cross-contract protection | All signed methods reject contract-to-contract calls |
| Intent schema pinning | SHA-256 hash prevents post-proposal schema changes |

## Concepts

### Wallets

A wallet is a named container with:
- An **owner** (creator, can be transferred)
- A set of **intents** defining allowed operations
- A set of **proposals** (pending, approved, executed, cancelled)
- A **token allowlist** for FT reception
- Internal **balance tracking** for NEAR and FTs
- A **storage deposit** (0.5 NEAR required on creation)

Every wallet is created with 3 **meta-intents** for self-governance:
| Index | Intent | Purpose |
|-------|--------|---------|
| 0 | `AddIntent` | Add new operation types via proposal |
| 1 | `RemoveIntent` | Deactivate an intent |
| 2 | `UpdateIntent` | Modify intent parameters |

### Intents

All intent changes go through the meta-intent proposal flow. There is no owner bypass — the multisig is fully governed by its thresholds.

An intent defines an allowed operation:

```json
{
  "name": "Transfer NEAR",
  "template": "transfer {amount} yoctoNEAR to {recipient}",
  "proposers": ["alice.near", "bob.near"],
  "approvers": ["alice.near", "bob.near", "carol.near"],
  "approval_threshold": 2,
  "cancellation_threshold": 2,
  "timelock_seconds": 86400,
  "execution_gas_tgas": 50,
  "params": [
    { "name": "amount", "param_type": "U128", "max_value": "10000000000000000000000000" },
    { "name": "recipient", "param_type": "AccountId", "max_value": null }
  ]
}
```

### Proposals

A proposal is created when a proposer fills in parameters for an intent:

1. **Active** → awaiting approvals
2. **Approved** → threshold reached, awaiting execution (after timelock)
3. **Executed** → action performed
4. **Cancelled** → vetoed by cancellation threshold

Proposals can be **amended** by the original proposer (resets all votes, requires clear-signed message).

### Parameter Types

| Type | JSON Representation | Example |
|------|-------------------|---------|
| `AccountId` | String | `"bob.near"` |
| `U64` | Number or string | `1000` or `"1000"` |
| `U128` | **String** (avoids precision loss) | `"1000000000000000000000000"` |
| `String` | String | `"hello"` |
| `Bool` | Boolean | `true` |

> **Important**: Always pass `U128` values as strings. JavaScript `Number` loses precision above 2^53.

## Token & Balance Management

### NEAR Balances

The contract tracks NEAR per wallet internally:
- **Deposit NEAR**: Execute a "Deposit NEAR" intent with attached deposit
- **Transfer NEAR**: Debits from wallet's tracked balance, sends to recipient
- **View balance**: `get_wallet_near_balance(wallet_name)`

### FT (NEP-141) Support

The contract implements `ft_on_transfer` to receive tokens:
- Call `ft_transfer_call(contract_id, amount, wallet_name)` on the FT contract
- Tokens are credited to the named wallet's internal balance
- **Token allowlist**: Empty = accept all. Non-empty = only listed tokens accepted
- `add_allowed_token(wallet, token)` / `remove_allowed_token(wallet, token)` — owner only
- `get_ft_balance(wallet, token)` — view balance

Storage is charged per unique token tracked (100 bytes per token from the storage deposit).

## Contract API

### Deployed

- **Testnet (v3 era)**: `cmsig.kampouse.testnet`
- **Testnet (v4/v5 bench deployments)**: `benchv5.vault.kampy.testnet` and siblings under `vault.kampy.testnet` (see `testbench/README.md`)
- **Repo**: [github.com/Kampouse/nostr-msig](https://github.com/Kampouse/nostr-msig)

### Wallet Management

| Method | Payable | Description |
|--------|---------|-------------|
| `create_wallet(name)` | Yes (0.5 NEAR) | Create wallet with 3 meta-intents |
| `delete_wallet(name)` | No | Delete wallet, refund storage. No active proposals. |
| `transfer_ownership(wallet, new_owner)` | No | Transfer ownership, update meta-intents |

### Token Management

| Method | Description |
|--------|-------------|
| `add_allowed_token(wallet, token)` | Add FT to wallet's allowlist (owner only) |
| `remove_allowed_token(wallet, token)` | Remove FT from allowlist (owner only) |
| `ft_on_transfer(sender, amount, msg)` | NEP-141 receiver. `msg` = wallet name |

### Proposal Lifecycle

| Method | Signed | Description |
|--------|--------|-------------|
| `propose(wallet, intent, params, expires, pubkey, sig)` | Yes | Create proposal with clear-signed message |
| `amend_proposal(wallet, id, params, expires, pubkey, sig)` | Yes | Amend proposal (resets votes, proposer only) |
| `approve(wallet, id, approver_idx, sig, expires)` | Yes | Approve with clear-signed message |
| `cancel_vote(wallet, id, approver_idx, sig, expires)` | Yes | Cancel-vote with clear-signed message |
| `execute(wallet, id)` | Optional* | Execute approved proposal |
| `cleanup(wallet, id)` | No | Remove executed/cancelled proposal |

*`execute` is payable for "Deposit NEAR" intent; attaches NEAR which is credited to the wallet.

### Delegation

| Method | Description |
|--------|-------------|
| `delegate_approver(wallet, intent, idx, delegate)` | Delegate approver slot to another account. Pass own account to revoke. |

### Views

| Method | Returns |
|--------|---------|
| `get_wallet(name)` | Wallet info (owner, storage, allowed tokens) |
| `get_intent(wallet, index)` | Intent by index |
| `list_intents(wallet)` | All intents |
| `get_proposal(wallet, id)` | Proposal by ID |
| `list_proposals(wallet)` | All proposals |
| `get_proposal_message(wallet, id)` | The human-readable message |
| `get_wallet_near_balance(wallet)` | Tracked NEAR balance |
| `get_ft_balance(wallet, token)` | Tracked FT balance |
| `get_allowed_tokens(wallet)` | Token allowlist |
| `get_delegation(wallet, intent, idx)` | Delegate for approver slot |
| `get_event_nonce()` | Current event counter |

## Built-in Executions

| Intent Name | Parameters | Action |
|-------------|-----------|--------|
| `Transfer NEAR` | `amount` (U128), `recipient` (AccountId) | Sends yoctoNEAR from wallet balance |
| `Transfer FT` | `token` (AccountId), `amount` (U128), `recipient` (AccountId) | Calls `ft_transfer`, debits tracked balance |
| `Deposit NEAR` | `amount` (U128) | Credits attached deposit to wallet balance |
| Custom (any other name) | Any params | Emits `custom_execution` event |

## Events

All state changes emit NEP-297 compliant events with monotonic nonces:

```json
{
  "standard": "clear-msig",
  "version": "1.0.0",
  "event": "transfer_near",
  "nonce": 42,
  "data": {
    "wallet": "treasury",
    "recipient": "bob.near",
    "amount": "1000000000000000000000000"
  }
}
```

| Event | Trigger |
|-------|---------|
| `wallet_created` | Wallet created |
| `wallet_deleted` | Wallet deleted |
| `ownership_transferred` | Owner changed |
| `token_allowed` | FT added to allowlist |
| `intent_added_via_proposal` | Intent added via AddIntent proposal |
| `intent_removed` | Intent deactivated |
| `intent_updated` | Intent modified |
| `proposal_created` | Proposal created |
| `proposal_amended` | Proposal amended |
| `proposal_approved` | Approval threshold reached |
| `proposal_cancelled` | Cancellation threshold reached |
| `proposal_executed` | Proposal executed |
| `proposal_cleaned` | Proposal removed from storage |
| `transfer_near` | NEAR transferred |
| `transfer_ft` | FT transferred |
| `near_deposited` | NEAR deposited to wallet |
| `ft_received` | FT received by wallet |
| `delegation_set` | Approver delegated |
| `delegation_revoked` | Delegation removed |

## Message Building Reference

### Template Rendering

Placeholders `{param_name}` are replaced with parameter values:

| ParamType | Rendering |
|-----------|-----------|
| `AccountId` | As-is string |
| `U64` | Decimal string |
| `U128` | Full decimal string (no truncation) |
| `String` | As-is string |
| `Bool` | `"true"` or `"false"` |

### Actions

| Action | Context |
|--------|---------|
| `propose` | Creating a proposal |
| `approve` | Approving a proposal |
| `cancel` | Cancel-voting a proposal |
| `amend` | Amending a proposal |

## Threat Model

### Protected against

- Blind signing / opaque transactions
- Parameter tampering (signed into message)
- Cross-wallet / cross-proposal replay
- Expired signature reuse
- Unauthorized proposals (pubkey verified)
- Cross-contract call attacks (`assert_direct_call`)
- Template injection (`|`, newlines rejected)
- Intent schema drift (SHA-256 pinning)
- Proposal spam (100 per intent, 1 year max expiry)
- U128 precision loss (always strings)
- Balance overdraft (checked before transfer)
- Unauthorized cancellations (clear-signed)
- FT griefing (token allowlist + storage accounting)
- Owner bypass (no `add_intent`, all through governance)
- Owner-signature replay across contracts (v3 contract-id binding)
- Owner-signature replay across time (v3 64-slot nonce window)
- Stuck/dangerous states (v3 guardian pause)

### Trust assumptions

| Trust | Who |
|-------|-----|
| ed25519 is secure | Cryptography |
| NEAR runtime verifies signatures | NEAR Protocol |
| Approvers control their keys | Key management |
| Contract logic is correct | **Needs audit** |

## Building & Deploying

### Prerequisites

- [Rust](https://rustup.rs/) (v4 needs rustc 1.93+ for near-sdk 5.29 — `rustup install 1.95.0`; note 1.97 aborts inside cargo-near, 1.86 cannot compile near-sdk 5.29)
- [cargo-near](https://github.com/near/cargo-near) (`cargo install cargo-near`)
- [near-cli-rs](https://docs.near.org/tools/near-cli-rs) ≥0.30 (`cargo install near-cli-rs`; needed for gas-key TransactionV1 signing)
- A NEAR account with enough NEAR for deployment + storage

### Build

```bash
cd contract
cargo +1.95.0 near build non-reproducible-wasm
```

Output: `target/near/clear_msig.wasm` (~630KB)

**Toolchain note:** newer default rustc (≥1.87) makes `cargo-near` abort with *"wasm compiled with 1.87.0 or newer rust toolchain is currently not compatible with nearcore VM"*. Build with a pinned toolchain instead:

```bash
cd contract
cargo +1.86.0 near build non-reproducible-wasm
```

(Build from `contract/` — the workspace root fails.) A ~630KB wasm needs **~7+ NEAR** on the contract account for storage staking; fund accordingly before deploying.

### Deploy (Fresh)

```bash
# 1. Create a subaccount for the contract (recommended)
near account create-account fund-myself <contract-id> '5 NEAR' \
  sign-as <your-account> network-config testnet sign-with-keychain send

# 2. Deploy contract code — then VERIFY the code hash (near CLI artifact cache!)
near contract deploy <contract-id> use-file target/near/clear_msig.wasm \
  without-init-call network-config testnet sign-with-keychain send
# or, hash-verified:  node deploy2.cjs <contract-id> target/near/clear_msig/clear_msig.wasm

# 3. Initialize (v3: pass the owner npub set)
near call <contract-id> new --accountId <your-account> --networkId testnet \
  --args '{"owner_npubs": ["<64-char-hex-npub>"]}'
```

### Deploy (Upgrade)

```bash
# Deploy new code over existing contract (preserves state if struct fields are compatible)
near contract deploy <contract-id> use-file target/near/clear_msig.wasm \
  without-init-call network-config testnet sign-with-keychain send
```

> ⚠️ If struct fields changed (e.g., new fields on Wallet/Intent/Proposal), existing state will fail to deserialize. v4 ships a `migrate()` init (`#[init(ignore_state)]`) that converts v3 state — after deploying v4 over v3 call `migrate()` once:
>
> ```bash
> near contract call-function as-transaction <contract-id> migrate json-args '{}' \
>   prepaid-gas '50 Tgas' attached-deposit '0 NEAR' sign-as <contract-id> \
>   network-config testnet sign-with-keychain send
> ```
>
> Until migrate runs, every view call panics with `Cannot deserialize the contract state`.

### First Wallet

```bash
# Create wallet (requires 0.5 NEAR storage deposit)
near contract call-function as-transaction <contract-id> create_wallet \
  json-args '{"name":"treasury"}' \
  prepaid-gas '30.0 Tgas' attached-deposit '0.5 NEAR' \
  sign-as <your-account> network-config testnet sign-with-keychain send
```

### Add an Intent (via Meta-Intent Proposal)

Since `add_intent` is removed, all intents go through the AddIntent governance flow:

```bash
# 1. Propose adding a Transfer NEAR intent
EXPIRY=$(python3 -c "import time; print(int(time.time()) + 86400)")
EXPIRY_NS="${EXPIRY}000000000"

# Build and sign the message (see reference/index.ts for client-side signing)
# Then call propose() with the signed message

# 2. Approve
# 3. Execute — intent is now active
```

Or use the TypeScript client:

```typescript
import { ClearMsig, nearToYocto, expiryFromNow } from './reference';
const client = new ClearMsig(contractId, 'testnet');

// Propose AddIntent
await client.propose('treasury', 0, {
  hash: '<intent-definition-hash>',
  name: 'Transfer NEAR',
  template: 'transfer {amount} yoctoNEAR to {recipient}',
  proposers: JSON.stringify(['alice.testnet']),
  approvers: JSON.stringify(['alice.testnet', 'bob.testnet']),
  approval_threshold: '2',
  timelock_seconds: '0',
  execution_gas_tgas: '50',
  params: JSON.stringify([
    { name: 'amount', param_type: 'U128', max_value: null },
    { name: 'recipient', param_type: 'AccountId', max_value: null },
  ]),
}, keyPair, account, { expiresAtNs: expiryFromNow(86400) });
```

### Mainnet Deployment

Same steps, but:
- Replace `testnet` with `mainnet`
- Use `--networkId mainnet`
- Ensure your account has enough NEAR (5+ recommended for contract account)
- **Get an audit first** if handling real funds

### Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `ERR_STORAGE_DEPOSIT` | Less than 0.5 NEAR attached | Add `attached-deposit '0.5 NEAR'` |
| `ERR_WALLET_EXISTS` | Wallet name already taken | Use a different name |
| `Cannot deserialize value with Borsh` | State incompatible after upgrade | Delete account and redeploy, or add migration |
| `ERR_DIRECT_CALL_REQUIRED` | Called from another contract | Must be a direct user transaction |
| `ERR_TOKEN_NOT_ALLOWED` | FT not on wallet's allowlist | Call `add_allowed_token` first |
| `ERR_INSUFFICIENT_NEAR` | Wallet balance too low | Deposit NEAR first |
| `ERR_MAX_PROPOSALS` | 100 active proposals on this intent | Wait for proposals to expire or execute |

## Reference Implementation

TypeScript client in `reference/index.ts`.

```typescript
import { ClearMsig, nearToYocto, expiryFromNow } from './reference';

const client = new ClearMsig('cmsig.kampouse.testnet', 'testnet');

// Create wallet (0.5 NEAR deposit)
await client.createWallet(account, 'treasury');

// Propose transfer
const { proposalId, message } = await client.propose(
  'treasury', 3,
  { amount: nearToYocto('1.5'), recipient: 'bob.testnet' },
  keyPair, account,
  { expiresAtNs: expiryFromNow(86400) },
);

// Approve
await client.approve('treasury', proposalId, 0, bobKeyPair, account, {
  expiresAtNs: expiryFromNow(86400),
});

// Execute
await client.execute(account, 'treasury', proposalId);
```

### Example

```bash
npx ts-node examples/full-flow.ts
```

## Project Structure

```
clear-msig/
├── contract/
│   └── src/
│       ├── lib.rs       # Contract state, wallet/intent/proposal CRUD
│       ├── execute.rs   # Proposal execution (NEAR, FT, deposit, custom)
│       ├── ft.rs        # NEP-141 receiver, balance tracking, allowlist
│       └── message.rs   # Clear-signing message builder & ed25519 verification
├── reference/
│   └── index.ts         # TypeScript client (reference implementation)
├── examples/
│   └── full-flow.ts     # Full flow demo
└── README.md
```

## License

MIT
