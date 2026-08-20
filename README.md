# nostr-msig

**Clear-signing multisig for NEAR Protocol — with agent delegation (v5).**

> NEAR Protocol port of [ChewingGlass/clear-msig](https://github.com/ChewingGlass/clear-msig), the original clear-sign multisig built for Solana on [Quasar](https://github.com/blueshift-gg/quasar).

Signers approve **human-readable messages**, not opaque transaction bytes. Every authority — owner, guardian, agent — is a **nostr identity** (npub). Agents act autonomously via **method-scoped, self-funded gas keys**: no relayer, no full-access key, ever.

**Status:** v5 proven live on testnet · 23 invariants formally verified ([Verus](formal-verification/)) · 16/16 unit tests · [one-command re-verification](testbench/)

## How It Works

1. **Intents** define what a wallet can do (transfer NEAR/FTs, deposit, custom actions) — with proposers, approvers, thresholds, timelocks
2. **Proposals** fill in the parameters and generate a human-readable message
3. **Signers** read the message and sign it with their nostr key
4. **Execution** happens once enough approvals are collected (after timelock)

```
expires 1893456000.000000000: propose transfer 1.5 NEAR to bob.near | wallet: treasury proposal: 0 | contract: msig.example.testnet
```

No ambiguity. Signers know exactly what they're approving.

## The Nostr Angle

Why **nostr**-msig? Because authority is held by **nostr identities** — `npub`s, BIP-340 x-only public keys:

- **You sign with your nostr key.** The signature is BIP-340 schnorr over `sha256(message)` — the exact key format and scheme used by every nostr client (Damus, Primal, Amethyst…). If you have a nostr keypair, you already have a signer key.
- **Nostr identities, not NEAR accounts, hold authority.** Owners are npubs, the guardian is an npub, and v5 agents are *independent nostr identities* that never hold a NEAR full-access key.
- **Nostr *keys*, not the nostr *network*.** The contract never talks to relays — it verifies schnorr signatures on-chain. No relay dependency; the key format is just a well-tooled, human-ownable identity standard.

Payoff: key management, backup, and portability come from the nostr ecosystem (nsec bunkers, hardware signers) instead of a bespoke scheme.

## v5 Agent Delegation (Current)

The flagship: **scoped agent keys that act autonomously on a wallet.** Proven live on testnet — propose → agent-npub approve (a second, independent nostr identity) → execute, all via pure-JS TransactionV1 gas-key transactions; 0.02Ⓝ moved exactly; out-of-scope agent execute rejected at the protocol level; drain + revoke swept all 13 gas keys, 0.249Ⓝ recovered, zero keys left.

### Method-scoped session keys

`add_session_key` takes a `methods` parameter — the gas key is scoped to a subset of `[submit_action, session_ping, propose, approve, execute, amend, cancel_vote]` at the **protocol level**. Widening the *transport* scope never widens *authority*: governance methods still verify their own nostr signatures internally. **The gas key only pays postage — the npub signature still gates every action.**

Typical setup:
- **Owner key**: `[submit_action, session_ping, propose, approve, execute]`
- **Agent key**: `[approve, session_ping]` — co-signs approvals on its own gas budget, nothing else

### The agent flow (proven on-chain)

1. Owner proposes a transfer (e.g. an `AgentTransfer` intent where the agent npub is an approver)
2. **The agent approves via its own scoped gas key** — self-funded, no owner signature on the transaction
3. Owner (or a delegated key) executes → funds move
4. Out-of-scope calls are rejected by the runtime before contract logic runs
5. Cleanup: drain the gas-key escrow, revoke — keys vanish

Guardrails (all on-chain): wallet ledger debited for key funding, minimum wallet reserve, lifetime funding cap (≤1Ⓝ per key), pause blocks sessions, sessions hard-bound to one wallet.

### Formal verification

Core invariants machine-verified with [Verus](https://github.com/verus-lang/verus) — **23 properties, 0 errors**. Highlights:

| ID | Property |
|----|----------|
| P7 | Gas-escrow conservation: `funded == burned + drained + balance`; overdraft unrepresentable |
| P8 | Method-scope enforcement: an approve-only agent key can never propose/execute/submit |
| P9 | Nonce-window replay resistance: consumed nonces can never be consumed again |

Full table + how to re-run: [formal-verification/](formal-verification/)

### Verify it yourself

```bash
cd testbench && npm install && node run.js
```

One command: build, deploy to a fresh subaccount, exercise the full session-key/agent surface on testnet, write machine-checkable verdict JSONs (~8.7Ⓝ). See [testbench/README.md](testbench/README.md). A consumer-mode UI mockup lives at [testbench/mockup.png](testbench/mockup.png).

## Version History

| Version | What it added |
|---------|---------------|
| v1–v2 | Core clear-signing multisig: intents, proposals, wallets, FT support |
| v3 | Security hardening: multi-owner npub set, guardian pause, contract-id binding, 64-slot nonce window, relayer payouts |
| v4 | Relayer-free session keys via [NEP-611](https://github.com/near/NEPs/pull/611) gas keys |
| **v5** | **Method-scoped session keys + full agent delegation (current)** |

Full engineering detail per version: [docs/version-history.md](docs/version-history.md)

## Concepts

A **wallet** is a named container with an owner, a set of **intents**, active **proposals**, a token allowlist, internal balance tracking, and a 0.5 NEAR storage deposit. Every wallet is created with 3 **meta-intents** (AddIntent / RemoveIntent / UpdateIntent) for self-governance — there is no owner bypass; the multisig is fully governed by its thresholds.

Proposal lifecycle: **Active → Approved → Executed** (or **Cancelled**). Proposals can be amended by the proposer (resets votes).

Full API (methods, views, events, message formats, troubleshooting): [docs/API.md](docs/API.md)

## Build & Deploy

```bash
# Prereqs: rustup (1.95.0 toolchain), cargo-near, near-cli-rs ≥0.30
cd contract
cargo +1.95.0 near build non-reproducible-wasm   # → target/near/clear_msig.wasm (~630KB)
```

Deploy to a fresh subaccount (needs ~7+ NEAR for storage staking), then init:

```bash
near contract call-function as-transaction <contract-id> new json-args '{"owner_npubs": ["<64-char-hex-npub>"]}' \
  prepaid-gas '50 Tgas' attached-deposit '0 NEAR' \
  sign-as <contract-id> network-config testnet sign-with-keychain send
```

Gotchas worth knowing before your first deploy:
- **Toolchain pin**: rustc 1.95 (≥1.97 aborts in cargo-near; ≤1.86 can't compile near-sdk 5.29). Build from `contract/`, not the workspace root.
- **Verify the code hash** after deploying — near-cli-rs caches wasm artifacts and can silently deploy stale code (`node deploy2.cjs` does hash-verified deploys).
- **Upgrades over old state** need one `migrate()` call after deploying.
- Testnet deployments: `benchv5.vault.kampy.testnet` (v5 bench, see testbench) · `cmsig.kampouse.testnet` (v3-era).

**Mainnet:** same steps, `--networkId mainnet`, 5+ NEAR on the contract account — **get an audit first** if handling real funds.

## Threat Model

Protected against: blind signing, parameter tampering, cross-wallet/proposal replay, expired-signature reuse, unauthorized proposals, cross-contract call attacks, template injection, intent schema drift, proposal spam, U128 precision loss, balance overdraft, FT griefing, owner bypass, cross-contract signature replay, nonce replay, and stuck states (guardian pause).

Trust assumptions: schnorr/ed25519 secure · NEAR runtime verifies signatures · approvers control their keys · contract logic correct — **needs audit**.

## Project Structure

```
nostr-msig/
├── contract/             # Rust contract (lib, execute, ft, message, sessions)
├── formal-verification/  # Verus proofs — 23 invariants
├── testbench/            # One-command testnet verification harness + verdicts
├── reference/            # TypeScript client
├── examples/             # full-flow.ts
├── e2e-v3.cjs, e2e-v4.cjs  # version-specific end-to-end suites
└── docs/                 # version-history.md, API.md
```

## License

MIT
