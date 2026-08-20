# Contract API Reference

Full method tables, events, and message formats. For concepts and the pitch, see the [README](../README.md).

## Features

| Feature | Description |
|---------|-------------|
| Clear-signing | Human-readable messages signed with BIP-340 schnorr (nostr keys) |
| Intent-based governance | Define allowed operations, proposers, approvers, thresholds |
| Meta-intents | Self-governance: AddIntent, RemoveIntent, UpdateIntent |
| Proposal lifecycle | Propose → Amend → Approve → Execute (with timelock) |
| NEP-141 FT support | Receive, hold, and transfer fungible tokens |
| Token allowlists | Per-wallet FT allowlist to prevent griefing |
| Balance tracking | Internal accounting for NEAR and FTs per wallet |
| Delegation | Approvers can delegate their vote to another account |
| Ownership transfer | Owner can transfer wallet ownership (meta-intents updated) |
| Proposal amendment | Proposer can amend active proposals (resets votes) |
| Wallet deletion | Owner can delete wallet, storage deposit refunded |
| Event nonces | Monotonic counter for strict event ordering |
| Configurable gas | Per-intent execution gas (default 50, max 300 Tgas) |
| Storage accounting | Tracks actual bytes, accurate refunds |
| Cross-contract protection | All signed methods reject contract-to-contract calls |
| Intent schema pinning | SHA-256 hash prevents post-proposal schema changes |
| Session keys (v4) | Relayer-free submission via NEP-611 gas keys |
| Agent delegation (v5) | Method-scoped keys, independent nostr identities |

## Parameter Types

| Type | JSON Representation | Example |
|------|-------------------|---|
| `AccountId` | String | `"bob.near"` |
| `U64` | Number or string | `1000` or `"1000"` |
| `U128` | **String** (avoids precision loss) | `"1000000000000000000000000"` |
| `String` | String | `"hello"` |
| `Bool` | Boolean | `true` |

> **Important**: Always pass `U128` values as strings. JavaScript `Number` loses precision above 2^53.

## Wallet Management

| Method | Payable | Description |
|--------|---------|-------------|
| `create_wallet(name)` | Yes (0.5 NEAR) | Create wallet with 3 meta-intents |
| `delete_wallet(name)` | No | Delete wallet, refund storage. No active proposals. |
| `transfer_ownership(wallet, new_owner)` | No | Transfer ownership, update meta-intents |

## Token Management

| Method | Description |
|---|---|
| `add_allowed_token(wallet, token)` | Add FT to wallet's allowlist (owner only) |
| `remove_allowed_token(wallet, token)` | Remove FT from wallet's allowlist (owner only) |
| `ft_on_transfer(sender, amount, msg)` | NEP-141 receiver. `msg` = wallet name |

## Proposal Lifecycle

| Method | Signed | Description |
|--------|--------|-------------|
| `propose(wallet, intent, params, expires, pubkey, sig)` | Yes | Create proposal with clear-signed message |
| `amend_proposal(wallet, id, params, expires, pubkey, sig)` | Yes | Amend proposal (resets votes, proposer only) |
| `approve(wallet, id, approver_idx, sig, expires)` | Yes | Approve with clear-signed message |
| `cancel_vote(wallet, id, approver_idx, sig, expires)` | Yes | Cancel-vote with clear-signed message |
| `execute(wallet, id)` | Optional* | Execute approved proposal |
| `cleanup(wallet, id)` | No | Remove executed/cancelled proposal |

*`execute` is payable for "Deposit NEAR" intent; attaches NEAR which is credited to the wallet.

## Sessions & Agents (v4/v5)

See [version-history.md](version-history.md) for the full v4 method table, NEP-611 mechanics, and message formats. v5 adds the `methods` scope parameter to `add_session_key` (see README).

## Delegation

| Method | Description |
|---|---|
| `delegate_approver(wallet, intent, idx, delegate)` | Delegate approver slot to another account. Pass own account to revoke. |

## Views

| Method | Returns |
|---|---|
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
| `get_owner_nonce()` | Owner nonce-window base |
| `get_version()` | Contract version |

## Built-in Executions

| Intent Name | Parameters | Action |
|-------------|-------------|--------|
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
  "data": { "wallet": "treasury", "recipient": "bob.near", "amount": "1000000000000000000000000" }
}
```

| Event | Trigger |
|---|---|
| `wallet_created` / `wallet_deleted` | Wallet lifecycle |
| `ownership_transferred` | Owner changed |
| `token_allowed` | FT added to allowlist |
| `intent_added_via_proposal` / `intent_removed` / `intent_updated` | Meta-intent governance |
| `proposal_created` / `proposal_amended` / `proposal_approved` / `proposal_cancelled` / `proposal_executed` / `proposal_cleaned` | Proposal lifecycle |
| `transfer_near` / `transfer_ft` / `near_deposited` / `ft_received` | Balance movements |
| `delegation_set` / `delegation_revoked` | Approver delegation |
| `session_key_added` / `session_key_refreshed` / `session_key_revoked` | Session/gas-key lifecycle (v4+) |

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
|---|---|
| `propose` | Creating a proposal |
| `approve` | Approving a proposal |
| `cancel` | Cancel-voting a proposal |
| `amend` | Amending a proposal |

## Reference Client (TypeScript)

```typescript
import { ClearMsig, nearToYocto, expiryFromNow } from './reference';

const client = new ClearMsig('<contract-id>', 'testnet');

await client.createWallet(account, 'treasury');                    // 0.5 NEAR deposit
const { proposalId, message } = await client.propose(              // propose transfer
  'treasury', 3,
  { amount: nearToYocto('1.5'), recipient: 'bob.testnet' },
  keyPair, account, { expiresAtNs: expiryFromNow(86400) },
);
await client.approve('treasury', proposalId, 0, bobKeyPair, account, {
  expiresAtNs: expiryFromNow(86400),
});
await client.execute(account, 'treasury', proposalId);
```

Runnable demo: `npx ts-node examples/full-flow.ts`

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `ERR_STORAGE_DEPOSIT` | Less than 0.5 NEAR attached | Add `attached-deposit '0.5 NEAR'` |
| `ERR_WALLET_EXISTS` | Wallet name already taken | Use a different name |
| `Cannot deserialize value with Borsh` | State incompatible after upgrade | Run `migrate()`, or delete account and redeploy |
| `ERR_DIRECT_CALL_REQUIRED` | Called from another contract | Must be a direct user transaction |
| `ERR_TOKEN_NOT_ALLOWED` | FT not on wallet's allowlist | Call `add_allowed_token` first |
| `ERR_INSUFFICIENT_NEAR` | Wallet balance too low | Deposit NEAR first |
| `ERR_MAX_PROPOSALS` | 100 active proposals on that intent | Wait for expiry or execute |
| `ERR_NONCE_ALREADY_USED` | Replayed owner nonce | Use a fresh nonce |
| `ERR_NONCE_WINDOW_EXCEEDED` | Nonce outside the 64-slot window | Use a nonce within `[get_owner_nonce(), +64)` |
| `ERR_SESSION_WALLET_MISMATCH` | Session key used on wrong wallet | Sessions are hard-bound to one wallet |
