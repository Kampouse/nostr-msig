use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, Vector};
use near_sdk::json_types::U128;
use near_sdk::{
    env, log, near, near_bindgen, AccountId, BorshStorageKey, NearToken,
    PanicOnDefault, Promise, PromiseOrValue, PromiseResult,
};

mod ft;
mod message;

use base64::Engine;

use message::hex_encode;

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum proposal expiry: 1 year from now (nanoseconds)
const MAX_EXPIRY_NS: u64 = 365 * 24 * 60 * 60 * 1_000_000_000;
/// Maximum active proposals per intent
const MAX_ACTIVE_PROPOSALS: u32 = 100;
/// Maximum approvers per intent (bitmap is u64)
#[allow(dead_code)]
const MAX_APPROVERS: usize = 64;
/// Storage deposit per wallet (covers wallet + 3 meta-intents + headroom)
const STORAGE_DEPOSIT_YOCTO: u128 = 500_000_000_000_000_000_000_000; // 0.5 NEAR
/// Default execution gas for cross-contract calls (Tgas)
const DEFAULT_EXECUTION_GAS_TGAS: u64 = 50;
/// Maximum execution gas (Tgas)
const MAX_EXECUTION_GAS_TGAS: u64 = 300;

// ── Storage Keys ──────────────────────────────────────────────────────────

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum StorageKey {
    Wallets,
    Intents,
    Proposals,
    Delegations,
    WalletNames,
}

// ── Types ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[near(serializers = [borsh, json])]
pub enum IntentType {
    #[default]
    Custom,
    AddIntent,
    RemoveIntent,
    UpdateIntent,
    /// Transfer NEAR or FT tokens to a recipient
    Transfer,
    /// Deposit NEAR into the wallet's internal balance
    Deposit,
    /// Arbitrary cross-contract call
    Call,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[near(serializers = [borsh, json])]
pub enum ProposalStatus {
    #[default]
    Active,
    Approved,
    Executed,
    Cancelled,
}

#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub enum ParamType {
    AccountId,
    U64,
    U128,
    String,
    Bool,
}

#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct ParamDef {
    pub name: String,
    pub param_type: ParamType,
    pub max_value: Option<U128>,
}

#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct Intent {
    pub wallet_name: String,
    pub index: u32,
    pub intent_type: IntentType,
    pub name: String,
    pub template: String,
    pub proposers: Vec<AccountId>,
    pub approvers: Vec<AccountId>,
    /// Nostr npub hex strings (32-byte x-only public keys)
    pub nostr_approvers: Vec<String>,
    /// Total approvals needed (NEAR + nostr combined)
    pub approval_threshold: u16,
    pub cancellation_threshold: u16,
    pub timelock_seconds: u64,
    pub params: Vec<ParamDef>,
    /// Execution gas in teragas (default: 50)
    pub execution_gas_tgas: u64,
    pub active: bool,
    pub active_proposal_count: u32,
}

impl Intent {
    #[allow(dead_code)]
    fn is_proposer(&self, account: &AccountId) -> bool {
        self.proposers.contains(account)
    }

    #[allow(dead_code)]
    fn execution_gas(&self) -> near_sdk::Gas {
        let tgas = if self.execution_gas_tgas == 0 {
            DEFAULT_EXECUTION_GAS_TGAS
        } else {
            self.execution_gas_tgas.min(MAX_EXECUTION_GAS_TGAS)
        };
        near_sdk::Gas::from_tgas(tgas)
    }

    fn render_template(&self, param_values: &serde_json::Value) -> String {
        let mut result = self.template.clone();
        for param in &self.params {
            let placeholder = format!("{{{}}}", param.name);
            let value = match param_values.get(&param.name) {
                Some(v) => match param.param_type {
                    ParamType::AccountId => v.as_str().unwrap_or("unknown").to_string(),
                    ParamType::U64 => v.as_u64().map(|n| n.to_string()).unwrap_or_default(),
                    ParamType::U128 => v
                        .as_str()
                        .map(|s| s.to_string())
                        .or_else(|| match v {
                            serde_json::Value::Number(n) => Some(n.to_string()),
                            _ => None,
                        })
                        .unwrap_or_default(),
                    ParamType::String => v.as_str().unwrap_or("").to_string(),
                    ParamType::Bool => v.as_bool().map(|b| b.to_string()).unwrap_or_default(),
                },
                None => continue,
            };
            // Sanitize: reject message format characters to prevent injection
            assert!(
                !value.contains('|') && !value.contains('\n') && !value.contains('\r'),
                "Param '{}' contains illegal characters",
                param.name
            );
            result = result.replace(&placeholder, &value);
        }
        result
    }
}

#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct Proposal {
    pub id: u64,
    pub wallet_name: String,
    pub intent_index: u32,
    pub proposer: AccountId,
    pub status: ProposalStatus,
    pub proposed_at: u64,
    pub approved_at: u64,
    pub expires_at: u64,
    pub approval_bitmap: u64,
    pub cancellation_bitmap: u64,
    /// Nostr approver bitmaps (same indexing as nostr_approvers)
    pub nostr_approval_bitmap: u64,
    pub nostr_cancellation_bitmap: u64,
    pub param_values: String,
    pub message: String,
    /// SHA-256 of the intent's params schema at proposal time.
    /// Execution fails if the schema changed after proposal.
    pub intent_params_hash: String,
}

impl Proposal {
    fn approval_count(&self) -> u32 {
        self.approval_bitmap.count_ones() + self.nostr_approval_bitmap.count_ones()
    }

    fn cancellation_count(&self) -> u32 {
        self.cancellation_bitmap.count_ones() + self.nostr_cancellation_bitmap.count_ones()
    }

    #[allow(dead_code)]
    fn has_approved(&self, idx: usize) -> bool {
        (self.approval_bitmap & (1u64 << idx)) != 0
    }

    fn has_nostr_approved(&self, idx: usize) -> bool {
        (self.nostr_approval_bitmap & (1u64 << idx)) != 0
    }

    #[allow(dead_code)]
    fn set_approval(&mut self, idx: usize) {
        let mask = 1u64 << idx;
        self.cancellation_bitmap &= !mask;
        self.approval_bitmap |= mask;
    }

    fn set_nostr_approval(&mut self, idx: usize) {
        let mask = 1u64 << idx;
        self.nostr_cancellation_bitmap &= !mask;
        self.nostr_approval_bitmap |= mask;
    }

    #[allow(dead_code)]
    fn set_cancellation(&mut self, idx: usize) {
        let mask = 1u64 << idx;
        self.approval_bitmap &= !mask;
        self.cancellation_bitmap |= mask;
    }

    fn set_nostr_cancellation(&mut self, idx: usize) {
        let mask = 1u64 << idx;
        self.nostr_approval_bitmap &= !mask;
        self.nostr_cancellation_bitmap |= mask;
    }

    fn reset_votes(&mut self) {
        self.approval_bitmap = 0;
        self.cancellation_bitmap = 0;
        self.nostr_approval_bitmap = 0;
        self.nostr_cancellation_bitmap = 0;
        self.approved_at = 0;
    }
}

// ── Wallet Migration ──────────────────────────────────────────────────────

/// Old wallet format (V1) — no spending limits or relayer config.
/// Used only for Borsh deserialization of legacy state.
#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
struct WalletV1 {
    name: String,
    owner: AccountId,
    proposal_index: u64,
    intent_index: u32,
    created_at: u64,
    storage_deposit: u128,
    storage_used: u64,
    allowed_tokens: Vec<AccountId>,
    ft_token_count: u32,
}

impl From<WalletV1> for Wallet {
    fn from(v1: WalletV1) -> Self {
        Wallet {
            name: v1.name,
            owner: v1.owner,
            proposal_index: v1.proposal_index,
            intent_index: v1.intent_index,
            created_at: v1.created_at,
            storage_deposit: v1.storage_deposit,
            storage_used: v1.storage_used,
            allowed_tokens: v1.allowed_tokens,
            ft_token_count: v1.ft_token_count,
            // New fields get safe defaults
            call_allowed_receivers: Vec::new(),
            call_max_deposit: 0,
            daily_spend_limit: 0,
            daily_spend_reset_at: v1.created_at,
            daily_spend_used: 0,
            relayer_fee: 0,
            allowed_relayers: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct Wallet {
    pub name: String,
    pub owner: AccountId,
    pub proposal_index: u64,
    pub intent_index: u32,
    pub created_at: u64,
    /// Amount of NEAR deposited for storage (yoctoNEAR)
    pub storage_deposit: u128,
    /// Actual storage used (bytes), tracked for accurate refunds
    pub storage_used: u64,
    /// Tokens allowed to be received via ft_on_transfer.
    /// Empty = accept all (open), non-empty = allowlist only.
    pub allowed_tokens: Vec<AccountId>,
    /// Number of unique FT tokens tracked (for storage accounting)
    pub ft_token_count: u32,
    /// Allowed receiver contracts for Call intents (empty = all allowed)
    pub call_allowed_receivers: Vec<AccountId>,
    /// Max deposit per Call intent in yoctoNEAR (0 = no limit)
    pub call_max_deposit: u128,
    /// Max total spend per day in yoctoNEAR (0 = no limit)
    pub daily_spend_limit: u128,
    /// Timestamp of last daily spend reset (nanoseconds)
    pub daily_spend_reset_at: u64,
    /// Amount spent today in yoctoNEAR
    pub daily_spend_used: u128,
    /// Relayer fee in yoctoNEAR per execution (0 = free)
    pub relayer_fee: u128,
    /// Optional relayer allowlist (empty = anyone can relay)
    pub allowed_relayers: Vec<AccountId>,
}

impl Wallet {
    /// Check and enforce daily spend limit. Returns true if reset happened.
    fn enforce_spend_limit(&mut self, now_ns: u64) {
        if self.daily_spend_limit == 0 { return; }
        // Reset if more than 24h have passed
        let one_day_ns: u64 = 24 * 60 * 60 * 1_000_000_000;
        if now_ns >= self.daily_spend_reset_at + one_day_ns {
            self.daily_spend_used = 0;
            self.daily_spend_reset_at = now_ns;
        }
    }

    /// Track spending and enforce limits. Panics if over limit.
    fn track_spend(&mut self, amount: u128) {
        if self.daily_spend_limit == 0 { return; }
        let new_total = self.daily_spend_used + amount;
        assert!(
            new_total <= self.daily_spend_limit,
            "ERR_DAILY_SPEND_LIMIT: used {} + {} > limit {}",
            self.daily_spend_used, amount, self.daily_spend_limit
        );
        self.daily_spend_used = new_total;
    }

    /// Check if a receiver is allowed for Call intents
    fn is_call_receiver_allowed(&self, receiver: &AccountId) -> bool {
        self.call_allowed_receivers.is_empty() || self.call_allowed_receivers.contains(receiver)
    }

    /// Check if a relayer is allowed
    #[allow(dead_code)]
    fn is_relayer_allowed(&self, relayer: &AccountId) -> bool {
        self.allowed_relayers.is_empty() || self.allowed_relayers.contains(relayer)
    }
}

// ── Composite keys ─────────────────────────────────────────────────────────

fn intent_key(wallet: &str, index: u32) -> String {
    format!("{}:i:{}", wallet, index)
}

fn proposal_key(wallet: &str, id: u64) -> String {
    format!("{}:p:{}", wallet, id)
}

fn delegation_key(wallet: &str, intent_index: u32, approver_index: usize) -> String {
    format!("{}:d:{}:{}", wallet, intent_index, approver_index)
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// SHA-256 of Borsh-serialized params schema.
fn hash_params(params: &[ParamDef]) -> String {
    let mut data = Vec::new();
    near_sdk::borsh::BorshSerialize::serialize(params, &mut data)
        .unwrap_or_else(|_| env::panic_str("Failed to serialize params"));
    let hash = env::sha256(&data);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Panic if the call comes from a contract (not a direct user transaction).
#[allow(dead_code)]
fn assert_direct_call() {
    assert_eq!(
        env::signer_account_id(),
        env::predecessor_account_id(),
        "ERR_DIRECT_CALL_REQUIRED"
    );
}

/// Get the hex representation of the signer's ed25519 public key (32 bytes, no prefix).
#[allow(dead_code)]
fn signer_pk_hex() -> String {
    let pk = env::signer_account_pk();
    let bytes = pk.into_bytes();
    // near-sdk PublicKey: 1-byte curve type prefix (0x00 = ed25519) + 32 bytes key
    let raw = if bytes.len() == 33 { &bytes[1..] } else { &bytes[..] };
    hex_encode(raw)
}

/// Build a JSON string safely using serde_json (no string formatting for JSON).
fn safe_json_ft_transfer(recipient: &str, amount: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "receiver_id": recipient,
        "amount": amount,
        "msg": ""
    }))
    .unwrap_or_else(|_| env::panic_str("ERR_JSON_SERIALIZE"))
}

// ── Contract ───────────────────────────────────────────────────────────────

#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
#[near_bindgen]
pub struct Contract {
    /// Nostr npub hex (32-byte x-only public key) of the contract owner.
    /// All admin actions require a schnorr signature from this key.
    /// Contract version for migration tracking.
    version: u32,
    owner_npub: String,
    wallets: LookupMap<String, Wallet>,
    intents: LookupMap<String, Intent>,
    proposals: LookupMap<String, Proposal>,
    delegations: LookupMap<String, AccountId>,
    event_nonce: u64,
    /// Monotonic counter for replay protection. Each owner action increments this.
    owner_nonce: u64,
    /// Ordered list of wallet names for enumeration.
    wallet_names: Vector<String>,
    /// Emergency pause flag — when true, only unpause() works.
    paused: bool,
    /// Reentrancy guard — true while executing a cross-contract call.
    locked: bool,
}

#[near_bindgen]
impl Contract {
    /// State migration: called on deserialization to handle new fields.
    #[allow(dead_code)]
    fn init_state(&mut self) {
        if self.paused {} // ensure field exists on old state
        if self.version == 0 { self.version = 2; } // migration from v0/v1
    }

    /// Assert contract is not paused.
    fn assert_not_paused(&self) {
        assert!(!self.paused, "ERR_CONTRACT_PAUSED");
    }

    /// Assert not in a cross-contract call (reentrancy guard).
    fn assert_not_locked(&self) {
        assert!(!self.locked, "ERR_REENTRANCY");
    }

    /// Emergency pause — blocks all state-changing calls except unpause.
    pub fn pause(&mut self, signature: String, expires_at: u64) {
        self.verify_owner("pause", &signature, expires_at);
        self.paused = true;
        self.emit_event("contract_paused", serde_json::json!({}));
        log!("Contract paused");
    }

    /// Unpause — restores normal operation.
    pub fn unpause(&mut self, signature: String, expires_at: u64) {
        self.verify_owner("unpause", &signature, expires_at);
        self.paused = false;
        self.emit_event("contract_unpaused", serde_json::json!({}));
        log!("Contract unpaused");
    }

    /// Check if contract is paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Get contract version.
    pub fn get_version(&self) -> u32 {
        self.version
    }

    // ── Wallet Storage Helpers (with migration) ──────────────────────

    /// Get a wallet, automatically migrating from old format if needed.
    /// Writes back the migrated version so future reads are V2-native.
    fn wallet_get(&mut self, name: &str) -> Option<Wallet> {
        let key = name.to_string();
        // Try V2 (current) deserialization first
        if let Some(wallet) = self.wallets.get(&key) {
            return Some(wallet);
        }
        // V2 failed — try V1 migration via raw storage
        let storage_key = {
            let mut k = Vec::new();
            near_sdk::borsh::BorshSerialize::serialize(&StorageKey::Wallets, &mut k).unwrap();
            near_sdk::borsh::BorshSerialize::serialize(&key, &mut k).unwrap();
            k
        };
        if let Some(bytes) = env::storage_read(&storage_key) {
            if let Ok(v1) = WalletV1::try_from_slice(&bytes) {
                let wallet: Wallet = v1.into();
                self.wallets.insert(&key, &wallet);
                log!("Migrated wallet '{}' from V1 to V2", name);
                return Some(wallet);
            }
        }
        None
    }

    fn wallet_get_readonly(&self, name: &str) -> Option<Wallet> {
        self.wallets.get(&name.to_string())
    }

    fn wallet_insert(&mut self, name: &str, wallet: &Wallet) {
        self.wallets.insert(&name.to_string(), wallet);
    }

    fn wallet_remove(&mut self, name: &str) -> Option<Wallet> {
        self.wallets.remove(&name.to_string())
    }

    /// Initialize with the nostr npub of the owner.
    /// The owner controls everything — create wallets, add intents, propose.
    #[init]
    pub fn new(owner_npub: String) -> Self {
        assert!(!owner_npub.is_empty(), "ERR_EMPTY_OWNER_NPUB");
        Self {
            version: 2,
            owner_npub,
            wallets: LookupMap::new(StorageKey::Wallets),
            intents: LookupMap::new(StorageKey::Intents),
            proposals: LookupMap::new(StorageKey::Proposals),
            delegations: LookupMap::new(StorageKey::Delegations),
            event_nonce: 0,
            owner_nonce: 0,
            wallet_names: Vector::new(StorageKey::WalletNames),
            paused: false,
            locked: false,
        }
    }

    /// Verify the caller is the nostr owner via schnorr signature.
    fn verify_owner(&mut self, action: &str, signature: &str, expires_at: u64) {
        assert!(expires_at > env::block_timestamp(), "ERR_SIG_EXPIRED");
        let nonce = self.owner_nonce;
        let msg = format!("expires {}.000000000: {} | nonce: {} | contract: owner", expires_at, action, nonce);
        message::verify_schnorr_signature(&self.owner_npub, signature, &msg);
        self.owner_nonce += 1;
    }

    /// Verify owner without consuming nonce (for read-only checks or backward compat)
    #[allow(dead_code)]
    fn verify_owner_readonly(&self, action: &str, signature: &str, expires_at: u64) {
        assert!(expires_at > env::block_timestamp(), "ERR_SIG_EXPIRED");
        let msg = format!("expires {}.000000000: {} | contract: owner", expires_at, action);
        message::verify_schnorr_signature(&self.owner_npub, signature, &msg);
    }

    // ── Wallet Management ──────────────────────────────────────────────

    #[payable]
    pub fn create_wallet(&mut self, name: String, signature: String, expires_at: u64) {
        self.assert_not_paused();
        self.verify_owner(&format!("create_wallet:{}", name), &signature, expires_at);
        let deposit = env::attached_deposit();
        assert!(
            deposit.as_yoctonear() >= STORAGE_DEPOSIT_YOCTO,
            "ERR_STORAGE_DEPOSIT: need {} yoctoNEAR, got {}",
            STORAGE_DEPOSIT_YOCTO,
            deposit.as_yoctonear()
        );

        assert!(self.wallet_get(&name).is_none(), "ERR_WALLET_EXISTS");
        assert!(!name.is_empty(), "ERR_NAME_EMPTY");
        assert!(name.len() <= 64, "ERR_NAME_TOO_LONG");
        assert!(
            name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "ERR_NAME_INVALID_CHARS"
        );

        let owner_display = self.owner_npub.clone();
        let initial_storage = env::storage_usage();
        let wallet = Wallet {
            name: name.clone(),
            owner: env::predecessor_account_id(),
            proposal_index: 0,
            intent_index: 3,
            created_at: env::block_timestamp(),
            storage_deposit: deposit.as_yoctonear(),
            storage_used: 0,
            allowed_tokens: Vec::new(),
            ft_token_count: 0,
            call_allowed_receivers: Vec::new(),
            call_max_deposit: 0,
            daily_spend_limit: 0,
            daily_spend_reset_at: env::block_timestamp(),
            daily_spend_used: 0,
            relayer_fee: 0,
            allowed_relayers: Vec::new(),
        };
        self.wallet_insert(&name, &wallet);
        self.wallet_names.push(&name);
        self.create_meta_intents(&name, &env::predecessor_account_id());
        let storage_used = env::storage_usage() - initial_storage;

        // Update with actual storage usage
        let mut w = self.wallet_get(&name).unwrap();
        w.storage_used = storage_used;
        self.wallet_insert(&name, &w);

        self.emit_event("wallet_created", serde_json::json!({
            "wallet": name,
            "owner_npub": owner_display,
            "deposit": deposit.as_yoctonear().to_string(),
            "storage_used": storage_used,
        }));

        log!("Wallet '{}' created ({} bytes storage)", name, storage_used);
    }

    /// Test: verify a nostr schnorr signature. Returns true if valid.
    pub fn test_verify_nostr(
        &self,
        message: String,
        pubkey_hex: String,
        signature: String,
    ) -> bool {
        message::verify_schnorr_signature(&pubkey_hex, &signature, &message);
        true
    }

    pub fn delete_wallet(&mut self, name: String, signature: String, expires_at: u64) {
        self.assert_not_paused();
        self.verify_owner(&format!("delete_wallet:{}", name), &signature, expires_at);
        let wallet = self.wallet_get(&name).expect("ERR_WALLET_NOT_FOUND");

        for i in 0..wallet.intent_index {
            if let Some(intent) = self.intents.get(&intent_key(&name, i)) {
                assert!(
                    intent.active_proposal_count == 0,
                    "ERR_ACTIVE_PROPOSALS: intent #{} has {}",
                    i,
                    intent.active_proposal_count
                );
            }
        }

        // Collect delegation keys before removing intents
        let mut del_keys: Vec<String> = Vec::new();
        for i in 0..wallet.intent_index {
            if let Some(intent) = self.intents.get(&intent_key(&name, i)) {
                for j in 0..intent.approvers.len() {
                    del_keys.push(delegation_key(&name, i, j));
                }
            }
        }

        for i in 0..wallet.intent_index {
            self.intents.remove(&intent_key(&name, i));
        }
        for i in 0..wallet.proposal_index {
            self.proposals.remove(&proposal_key(&name, i));
        }
        for dkey in del_keys {
            self.delegations.remove(&dkey);
        }

        // Refund only the actual storage cost (20 yoctoNEAR per byte) + deposit remainder
        let storage_cost = NearToken::from_yoctonear(wallet.storage_used as u128)
    .saturating_mul(env::storage_byte_cost().as_yoctonear())
    .as_yoctonear();
        let refund = wallet.storage_deposit.saturating_sub(storage_cost);
        if refund > 0 {
            Promise::new(wallet.owner.clone()).transfer(NearToken::from_yoctonear(refund));
        }

        self.wallet_remove(&name);

        // Remove from wallet_names Vector (swap-remove)
        let len = self.wallet_names.len();
        let mut found_idx: Option<u64> = None;
        for i in 0..len {
            if let Some(n) = self.wallet_names.get(i) {
                if n == name {
                    found_idx = Some(i);
                    break;
                }
            }
        }
        if let Some(idx) = found_idx {
            self.wallet_names.swap_remove(idx);
        }

        self.emit_event("wallet_deleted", serde_json::json!({
            "wallet": name,
            "storage_used": wallet.storage_used,
            "refund": refund.to_string(),
        }));

        log!("Wallet '{}' deleted (refunded {} yocto)", name, refund);
    }

    pub fn transfer_ownership(&mut self, wallet_name: String, new_owner: AccountId, signature: String, expires_at: u64) {
        self.assert_not_paused();
        self.verify_owner(&format!("transfer_ownership:{}", wallet_name), &signature, expires_at);
        let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        assert_ne!(new_owner, wallet.owner, "ERR_ALREADY_OWNER");

        let old_owner = wallet.owner.clone();
        wallet.owner = new_owner.clone();
        self.wallet_insert(&wallet_name, &wallet);

        for i in 0..3u32 {
            let ikey = intent_key(&wallet_name, i);
            if let Some(mut intent) = self.intents.get(&ikey) {
                if let Some(pos) = intent.proposers.iter().position(|a| a == &old_owner) {
                    intent.proposers[pos] = new_owner.clone();
                }
                if let Some(pos) = intent.approvers.iter().position(|a| a == &old_owner) {
                    intent.approvers[pos] = new_owner.clone();
                }
                self.intents.insert(&ikey, &intent);
            }
        }

        self.emit_event("ownership_transferred", serde_json::json!({
            "wallet": wallet_name,
            "old_owner": old_owner.to_string(),
            "new_owner": new_owner.to_string(),
        }));

        log!("Ownership of '{}' transferred to {}", wallet_name, new_owner);
    }

    /// Rotate the contract owner's nostr key. Requires signature from the CURRENT nsec.
    /// After rotation, the new npub is used for all owner verification.
    pub fn rotate_owner_key(&mut self, new_npub: String, signature: String, expires_at: u64) {
        assert!(!new_npub.is_empty(), "ERR_EMPTY_NPUB");
        assert!(new_npub.len() == 64, "ERR_INVALID_NPUB_LEN: expected 64 hex chars");
        self.verify_owner("rotate_owner_key", &signature, expires_at);
        let old_npub = self.owner_npub.clone();
        self.owner_npub = new_npub.clone();
        self.emit_event("owner_key_rotated", serde_json::json!({
            "old_npub": old_npub,
            "new_npub": new_npub,
        }));
        log!("Owner key rotated: {} -> {}", old_npub, &new_npub[..16]);
    }

    /// Get the current owner nonce (for clients to include in signatures)
    pub fn get_owner_nonce(&self) -> u64 {
        self.owner_nonce
    }

    // ── Intent Management ──────────────────────────────────────────────

    /// Add a token to the wallet's FT allowlist. Owner only.
    /// Empty allowlist = accept all tokens.
    /// Once you add the first token, only listed tokens are accepted.
    pub fn add_allowed_token(&mut self, wallet_name: String, token: AccountId, signature: String, expires_at: u64) {
        self.assert_not_paused();
        self.verify_owner(&format!("add_allowed_token:{}", wallet_name), &signature, expires_at);
        let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        assert!(
            !wallet.allowed_tokens.contains(&token),
            "ERR_TOKEN_ALREADY_ALLOWED"
        );
        wallet.allowed_tokens.push(token.clone());
        self.wallet_insert(&wallet_name, &wallet);

        self.emit_event("token_allowed", serde_json::json!({
            "wallet": wallet_name,
            "token": token.to_string(),
        }));

        log!("Token '{}' allowed for wallet '{}'", token, wallet_name);
    }

    /// Remove a token from the wallet's FT allowlist. Owner only.
    pub fn remove_allowed_token(&mut self, wallet_name: String, token: AccountId, signature: String, expires_at: u64) {
        self.assert_not_paused();
        self.verify_owner(&format!("remove_allowed_token:{}", wallet_name), &signature, expires_at);
        let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        let original_len = wallet.allowed_tokens.len();
        wallet.allowed_tokens.retain(|t| t != &token);
        assert!(
            wallet.allowed_tokens.len() < original_len,
            "ERR_TOKEN_NOT_IN_LIST"
        );
        self.wallet_insert(&wallet_name, &wallet);

        self.emit_event("token_removed_from_allowlist", serde_json::json!({
            "wallet": wallet_name,
            "token": token.to_string(),
        }));

        log!("Token '{}' removed from allowlist for '{}'", token, wallet_name);
    }

    // ── Proposal Lifecycle ─────────────────────────────────────────────

    pub fn propose(
        &mut self,
        wallet_name: String,
        intent_index: u32,
        param_values: String,
        expires_at: u64,
        signature: String,
    ) {
        self.assert_not_paused();
        let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        let ikey = intent_key(&wallet_name, intent_index);
        let intent = self.intents.get(&ikey).expect("ERR_INTENT_NOT_FOUND");

        assert!(intent.active, "ERR_INTENT_INACTIVE");
        assert!(expires_at > env::block_timestamp(), "ERR_EXPIRED");
        assert!(expires_at <= env::block_timestamp() + MAX_EXPIRY_NS, "ERR_EXPIRY_TOO_FAR");
        assert!(intent.active_proposal_count < MAX_ACTIVE_PROPOSALS, "ERR_MAX_PROPOSALS");

        let params: serde_json::Value = serde_json::from_str(&param_values).expect("ERR_INVALID_JSON");
        self.validate_params(&intent, &params);

        let proposal_index = wallet.proposal_index;
        let msg = message::build_message(&wallet_name, proposal_index, expires_at, "propose", &intent, &params);

        // Verify nostr owner signature
        self.verify_owner(&format!("propose:{}:{}", wallet_name, proposal_index), &signature, expires_at);

        let proposal = Proposal {
            id: proposal_index,
            wallet_name: wallet_name.clone(),
            intent_index,
            proposer: env::predecessor_account_id(),
            status: ProposalStatus::Active,
            proposed_at: env::block_timestamp(),
            approved_at: 0,
            expires_at,
            approval_bitmap: 0,
            cancellation_bitmap: 0,
            nostr_approval_bitmap: 0,
            nostr_cancellation_bitmap: 0,
            param_values,
            message: msg.clone(),
            intent_params_hash: hash_params(&intent.params),
        };

        self.proposals.insert(&proposal_key(&wallet_name, proposal_index), &proposal);

        let mut intent_mut = intent.clone();
        intent_mut.active_proposal_count += 1;
        self.intents.insert(&ikey, &intent_mut);

        wallet.proposal_index = proposal_index + 1;
        self.wallet_insert(&wallet_name, &wallet);

        self.emit_event("proposal_created", serde_json::json!({
            "wallet": wallet_name, "proposal_id": proposal_index,
            "intent_index": intent_index, "message": msg,
        }));

        log!("Proposal #{} created for intent #{}", proposal_index, intent_index);
    }

    pub fn amend_proposal(
        &mut self,
        wallet_name: String,
        proposal_id: u64,
        param_values: String,
        expires_at: u64,
        signature: String,
    ) {
        self.assert_not_paused();
        let pkey = proposal_key(&wallet_name, proposal_id);
        let mut proposal = self.proposals.get(&pkey).expect("ERR_PROPOSAL_NOT_FOUND");

        assert!(proposal.status == ProposalStatus::Active, "ERR_NOT_ACTIVE");
        assert!(expires_at > env::block_timestamp(), "ERR_EXPIRED");
        assert!(expires_at <= env::block_timestamp() + MAX_EXPIRY_NS, "ERR_EXPIRY_TOO_FAR");

        let ikey = intent_key(&wallet_name, proposal.intent_index);
        let intent = self.intents.get(&ikey).expect("ERR_INTENT_NOT_FOUND");
        assert!(intent.active, "ERR_INTENT_INACTIVE");

        let params: serde_json::Value = serde_json::from_str(&param_values).expect("ERR_INVALID_JSON");
        self.validate_params(&intent, &params);

        let msg = message::build_message(&wallet_name, proposal_id, expires_at, "amend", &intent, &params);

        // Verify nostr owner signature
        self.verify_owner(&format!("amend:{}:{}", wallet_name, proposal_id), &signature, expires_at);

        proposal.reset_votes();
        proposal.param_values = param_values;
        proposal.expires_at = expires_at;
        proposal.message = msg;
        proposal.intent_params_hash = hash_params(&intent.params);

        self.proposals.insert(&pkey, &proposal);

        self.emit_event("proposal_amended", serde_json::json!({
            "wallet": wallet_name, "proposal_id": proposal_id,
        }));

        log!("Proposal #{} amended", proposal_id);
    }

    /// Approve a proposal using a nostr schnorr signature.
    /// `approver_index` indexes into `intent.nostr_approvers`.
    pub fn approve(
        &mut self,
        wallet_name: String,
        proposal_id: u64,
        approver_index: u16,
        pubkey_hex: String,
        signature: String,
        expires_at: u64,
    ) {
        self.assert_not_paused();
        self.verify_nostr_approver(
            wallet_name, proposal_id, approver_index, pubkey_hex, signature, expires_at, "approve",
        );
    }

    /// Cancel-vote a proposal using a nostr schnorr signature.
    pub fn cancel_vote(
        &mut self,
        wallet_name: String,
        proposal_id: u64,
        approver_index: u16,
        pubkey_hex: String,
        signature: String,
        expires_at: u64,
    ) {
        self.assert_not_paused();
        self.verify_nostr_approver(
            wallet_name, proposal_id, approver_index, pubkey_hex, signature, expires_at, "cancel",
        );
    }


    // ── Quick Execute (Solo User) ────────────────────────────────────

    /// One-call execution for solo users. Proposes, auto-approves, and
    /// executes in a single transaction. Only works when:
    /// - The caller is the owner (verified via nostr signature)
    /// - The intent has approval_threshold == 1
    /// - The owner's npub is in intent.nostr_approvers
    ///
    /// This lets a Nostr user do everything with a single signed message.
    #[payable]
    pub fn quick_execute(
        &mut self,
        wallet_name: String,
        intent_index: u32,
        param_values: String,
        expires_at: u64,
        signature: String,
    ) {
        self.assert_not_paused();
        // Verify owner signature for this action
        let action = format!("quick:{}:{}:{}", wallet_name, intent_index, &param_values.chars().take(64).collect::<String>());
        self.verify_owner(&action, &signature, expires_at);

        let ikey = intent_key(&wallet_name, intent_index);
        let intent = self.intents.get(&ikey).expect("ERR_INTENT_NOT_FOUND");
        assert!(intent.active, "ERR_INTENT_INACTIVE");
        assert!(intent.approval_threshold == 1, "ERR_NOT_SOLO: quick_execute only works with approval_threshold=1");

        // Check owner is a proposer
        let predecessor = env::predecessor_account_id();
        let owner_is_proposer = intent.proposers.is_empty() || intent.proposers.contains(&predecessor);
        assert!(owner_is_proposer, "ERR_NOT_PROPOSER: caller not in intent proposers");

        // Check owner is in nostr_approvers
        let owner_is_approver = intent.nostr_approvers.iter().any(|p| p == &self.owner_npub);
        assert!(owner_is_approver, "ERR_OWNER_NOT_APPROVER: owner must be in nostr_approvers");

        // Validate params
        let params: serde_json::Value = serde_json::from_str(&param_values).expect("ERR_INVALID_JSON");
        self.validate_params(&intent, &params);

        // Create proposal
        let wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        let proposal_id = wallet.proposal_index;
        let msg = message::build_message(&wallet_name, proposal_id, expires_at, "quick", &intent, &params);

        let proposal = Proposal {
            id: proposal_id,
            wallet_name: wallet_name.clone(),
            intent_index,
            proposer: env::predecessor_account_id(),
            status: ProposalStatus::Approved, // Auto-approved
            proposed_at: env::block_timestamp(),
            approved_at: env::block_timestamp(),
            expires_at,
            approval_bitmap: 0,
            cancellation_bitmap: 0,
            nostr_approval_bitmap: 1u64 << 0, // Owner approved
            nostr_cancellation_bitmap: 0,
            param_values: param_values.clone(),
            message: msg,
            intent_params_hash: hash_params(&intent.params),
        };

        let pkey = proposal_key(&wallet_name, proposal_id);
        self.proposals.insert(&pkey, &proposal);

        // Update wallet proposal index
        let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        wallet.proposal_index += 1;
        self.wallet_insert(&wallet_name, &wallet);

        // Update intent active_proposal_count
        let mut intent = intent;
        intent.active_proposal_count += 1;
        self.intents.insert(&ikey, &intent);

        self.emit_event("quick_proposed_and_approved", serde_json::json!({
            "wallet": wallet_name, "proposal_id": proposal_id, "intent_index": intent_index,
        }));
        log!("Proposal #{} quick-approved for intent #{}", proposal_id, intent_index);

        // Now execute it (inline the execution logic)
        self.execute_proposal(&wallet_name, proposal_id);
    }

    // ── Execution ────────────────────────────────────────────────────

    /// Execute an approved proposal. Requires owner nostr signature.
    /// Payable: allows attached deposit for "deposit NEAR" intent executions.
    #[payable]
    pub fn execute(&mut self, wallet_name: String, proposal_id: u64, signature: String, expires_at: u64) {
        self.assert_not_paused();
        self.verify_owner(&format!("execute:{}:{}", wallet_name, proposal_id), &signature, expires_at);
        self.execute_proposal(&wallet_name, proposal_id);
    }

    /// Internal execution logic shared by execute() and quick_execute().
    fn execute_proposal(&mut self, wallet_name: &String, proposal_id: u64) {
        let pkey = proposal_key(wallet_name, proposal_id);
        let mut proposal = self.proposals.get(&pkey).expect("ERR_PROPOSAL_NOT_FOUND");
        assert!(proposal.status == ProposalStatus::Approved, "ERR_NOT_APPROVED");
        assert!(proposal.expires_at > env::block_timestamp(), "ERR_PROPOSAL_EXPIRED");

        let ikey = intent_key(wallet_name, proposal.intent_index);
        let intent = self.intents.get(&ikey).expect("ERR_INTENT_NOT_FOUND");
        
        // Check timelock
        if intent.timelock_seconds > 0 {
            let elapsed = env::block_timestamp() as u128 - proposal.proposed_at as u128;
            let timelock_ns = (intent.timelock_seconds as u128) * 1_000_000_000u128;
            assert!(elapsed >= timelock_ns, "ERR_TIMELOCK_NOT_EXPIRED");
        }

        // Verify params haven't changed since proposal
        let current_hash = hash_params(&intent.params);
        assert_eq!(
            proposal.intent_params_hash, current_hash,
            "ERR_PARAMS_CHANGED: intent schema was modified after proposal"
        );

        let params: serde_json::Value = serde_json::from_str(&proposal.param_values).unwrap_or_default();
        let definition = params.get("definition").and_then(|v| v.as_str());

        match intent.intent_type {
            IntentType::AddIntent => {
                let new_intent: Intent = if let Some(def) = definition {
                    near_sdk::serde_json::from_str(def)
                        .expect("ERR_INVALID_INTENT_DEFINITION")
                } else if let Some(def_obj) = params.get("definition") {
                    near_sdk::serde_json::from_value(def_obj.clone())
                        .expect("ERR_INVALID_INTENT_DEFINITION")
                } else {
                    // Build intent from top-level params with defaults
                    let proposers: Vec<AccountId> = params.get("proposers")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().and_then(|s| s.parse().ok())).collect())
                        .unwrap_or_default();
                    let approvers: Vec<AccountId> = params.get("approvers")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().and_then(|s| s.parse().ok())).collect())
                        .unwrap_or_default();
                    let pdefs: Vec<ParamDef> = params.get("params")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| near_sdk::serde_json::from_value(v.clone()).ok()).collect())
                        .unwrap_or_default();
                    Intent {
                        wallet_name: wallet_name.clone(),
                        index: 0, // will be overwritten
                        intent_type: IntentType::Custom,
                        name: params.get("name").and_then(|v| v.as_str()).unwrap_or("Custom").to_string(),
                        template: params.get("template").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        proposers,
                        approvers,
                        nostr_approvers: params.get("nostr_approvers")
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default(),
                        approval_threshold: params.get("approval_threshold").and_then(|v| v.as_u64()).unwrap_or(1) as u16,
                        cancellation_threshold: params.get("cancellation_threshold").and_then(|v| v.as_u64()).unwrap_or(1) as u16,
                        timelock_seconds: params.get("timelock_seconds").and_then(|v| v.as_u64()).unwrap_or(0),
                        params: pdefs,
                        execution_gas_tgas: params.get("execution_gas_tgas").and_then(|v| v.as_u64()).unwrap_or(DEFAULT_EXECUTION_GAS_TGAS),
                        active: true,
                        active_proposal_count: 0,
                    }
                };
                let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
                let new_index = wallet.intent_index;
                self.intents.insert(&intent_key(&wallet_name, new_index), &new_intent);
                wallet.intent_index += 1;
                self.wallet_insert(&wallet_name, &wallet);
                log!("Intent #{} added to wallet {}", new_index, wallet_name);
            }
            IntentType::RemoveIntent => {
                let idx = params["index"].as_u64().expect("ERR_MISSING_INDEX") as u32;
                let mut ri = self.intents.get(&intent_key(&wallet_name, idx)).expect("ERR_INTENT_NOT_FOUND");
                ri.active = false;
                self.intents.insert(&intent_key(&wallet_name, idx), &ri);
                log!("Intent #{} deactivated", idx);
            }
            IntentType::UpdateIntent => {
                let idx = params["index"].as_u64().expect("ERR_MISSING_INDEX") as u32;
                let def = params.get("definition").and_then(|v| v.as_str());
                let updated: Intent = if let Some(d) = def {
                    near_sdk::serde_json::from_str(d).expect("ERR_INVALID_DEFINITION")
                } else {
                    // Merge: start from existing intent, overlay params
                    let mut existing = self.intents.get(&intent_key(&wallet_name, idx)).expect("ERR_INTENT_NOT_FOUND");
                    if let Some(v) = params.get("name").and_then(|v| v.as_str()) { existing.name = v.to_string(); }
                    if let Some(v) = params.get("template").and_then(|v| v.as_str()) { existing.template = v.to_string(); }
                    if let Some(v) = params.get("approval_threshold").and_then(|v| v.as_u64()) { existing.approval_threshold = v as u16; }
                    if let Some(v) = params.get("cancellation_threshold").and_then(|v| v.as_u64()) { existing.cancellation_threshold = v as u16; }
                    if let Some(v) = params.get("timelock_seconds").and_then(|v| v.as_u64()) { existing.timelock_seconds = v; }
                    if let Some(v) = params.get("execution_gas_tgas").and_then(|v| v.as_u64()) { existing.execution_gas_tgas = v; }
                    if let Some(v) = params.get("active").and_then(|v| v.as_bool()) { existing.active = v; }
                    if let Some(arr) = params.get("proposers").and_then(|v| v.as_array()) {
                        existing.proposers = arr.iter().filter_map(|v| v.as_str().and_then(|s| s.parse().ok())).collect();
                    }
                    if let Some(arr) = params.get("approvers").and_then(|v| v.as_array()) {
                        existing.approvers = arr.iter().filter_map(|v| v.as_str().and_then(|s| s.parse().ok())).collect();
                    }
                    if let Some(arr) = params.get("nostr_approvers").and_then(|v| v.as_array()) {
                        existing.nostr_approvers = arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                    }
                    if let Some(arr) = params.get("params").and_then(|v| v.as_array()) {
                        existing.params = arr.iter().filter_map(|v| near_sdk::serde_json::from_value(v.clone()).ok()).collect();
                    }
                    existing
                };
                self.intents.insert(&intent_key(&wallet_name, idx), &updated);
                log!("Intent #{} updated", idx);
            }
            IntentType::Custom => {
                // Keep string-matching for backwards compat with existing intents
                if intent.template.contains("deposit") || intent.name.to_lowercase().contains("deposit") {
                    self.execute_deposit(&wallet_name);
                } else if intent.template.contains("transfer") || intent.name.contains("transfer") {
                    self.execute_transfer(&wallet_name, &params);
                } else {
                    let truncated: String = proposal.param_values.chars().take(200).collect();
                    log!("Custom '{}' executed: {}", intent.name, truncated);
                }
            }
            IntentType::Deposit => {
                self.execute_deposit(&wallet_name);
            }
            IntentType::Transfer => {
                self.execute_transfer(&wallet_name, &params);
            }
            IntentType::Call => {
                self.execute_call(&wallet_name, &params);
            }
        }

        proposal.status = ProposalStatus::Executed;
        self.proposals.insert(&pkey, &proposal);
        let mut intent_mut = intent.clone();
        intent_mut.active_proposal_count = intent_mut.active_proposal_count.saturating_sub(1);
        self.intents.insert(&ikey, &intent_mut);
        self.emit_event("proposal_executed", serde_json::json!({
            "wallet": wallet_name, "proposal_id": proposal_id,
        }));
    }

    /// Remove an executed/cancelled proposal to reclaim storage. Owner only.
    pub fn cleanup(&mut self, wallet_name: String, proposal_id: u64, signature: String, expires_at: u64) {
        self.assert_not_paused();
        self.verify_owner(&format!("cleanup:{}:{}", wallet_name, proposal_id), &signature, expires_at);

        let pkey = proposal_key(&wallet_name, proposal_id);
        let proposal = self.proposals.get(&pkey).expect("ERR_PROPOSAL_NOT_FOUND");
        assert!(
            proposal.status == ProposalStatus::Executed || proposal.status == ProposalStatus::Cancelled,
            "ERR_NOT_EXECUTABLE: only executed or cancelled proposals can be cleaned up"
        );

        self.proposals.remove(&pkey);
        self.emit_event("proposal_cleaned", serde_json::json!({
            "wallet": wallet_name, "proposal_id": proposal_id,
        }));
        log!("Proposal #{} cleaned up from wallet '{}'", proposal_id, wallet_name);
    }

    // ── Views ──────────────────────────────────────────────────────────

    pub fn get_wallet(&self, name: String) -> Option<Wallet> {
        self.wallet_get_readonly(&name)
    }

    pub fn get_intent(&self, wallet_name: String, index: u32) -> Option<Intent> {
        self.intents.get(&intent_key(&wallet_name, index))
    }

    pub fn list_intents(&self, wallet_name: String) -> Vec<Intent> {
        let Some(wallet) = self.wallet_get_readonly(&wallet_name) else { return Vec::new(); };
        (0..wallet.intent_index)
            .filter_map(|i| self.intents.get(&intent_key(&wallet_name, i)))
            .collect()
    }

    pub fn get_proposal(&self, wallet_name: String, id: u64) -> Option<Proposal> {
        self.proposals.get(&proposal_key(&wallet_name, id))
    }

    /// List proposals — capped at 100 to prevent gas exhaustion.
    /// Use get_proposals_paginated for large wallets.
    pub fn list_proposals(&self, wallet_name: String) -> Vec<Proposal> {
        let Some(wallet) = self.wallet_get_readonly(&wallet_name) else { return Vec::new(); };
        let limit = wallet.proposal_index.min(100);
        let start = wallet.proposal_index.saturating_sub(limit);
        (start..wallet.proposal_index)
            .filter_map(|i| self.proposals.get(&proposal_key(&wallet_name, i)))
            .collect()
    }

    pub fn get_proposal_message(&self, wallet_name: String, id: u64) -> Option<String> {
        self.proposals.get(&proposal_key(&wallet_name, id)).map(|p| p.message)
    }

    pub fn get_allowed_tokens(&self, wallet_name: String) -> Vec<AccountId> {
        self.wallet_get_readonly(&wallet_name)
            .map(|w| w.allowed_tokens)
            .unwrap_or_default()
    }

    pub fn get_delegation(&self, wallet_name: String, intent_index: u32, approver_index: u16) -> Option<AccountId> {
        self.delegations.get(&delegation_key(&wallet_name, intent_index, approver_index as usize))
    }

    pub fn get_event_nonce(&self) -> u64 {
        self.event_nonce
    }

    /// List all wallet names on this contract.
    pub fn list_wallets(&self, from_index: u64, limit: u64) -> Vec<String> {
        let start = from_index.min(self.wallet_names.len());
        let end = (start + limit).min(self.wallet_names.len());
        (start..end)
            .filter_map(|i| self.wallet_names.get(i))
            .collect()
    }

    /// Get total number of wallets.
    pub fn get_wallet_count(&self) -> u64 {
        self.wallet_names.len()
    }

    /// Get comprehensive wallet state: wallet, intents, balances, recent proposals
    pub fn get_wallet_state(&self, wallet_name: String) -> serde_json::Value {
        let wallet = match self.wallet_get_readonly(&wallet_name) {
            Some(w) => w,
            None => return serde_json::json!({"error": "ERR_WALLET_NOT_FOUND"}),
        };

        let intents: Vec<Intent> = (0..wallet.intent_index)
            .filter_map(|i| self.intents.get(&intent_key(&wallet_name, i)))
            .collect();

        let near_balance = self.get_wallet_near_balance(wallet_name.clone()).0;

        // Get recent proposals (last 10)
        let proposals: Vec<Proposal> = if wallet.proposal_index > 10 {
            (wallet.proposal_index - 10..wallet.proposal_index)
                .filter_map(|i| self.proposals.get(&proposal_key(&wallet_name, i)))
                .collect()
        } else {
            (0..wallet.proposal_index)
                .filter_map(|i| self.proposals.get(&proposal_key(&wallet_name, i)))
                .collect()
        };

        serde_json::json!({
            "wallet": wallet,
            "intents": intents,
            "near_balance": near_balance.to_string(),
            "recent_proposals": proposals,
        })
    }

    /// Get paginated proposal history
    pub fn get_proposals_paginated(
        &self,
        wallet_name: String,
        from: u64,
        limit: u64,
    ) -> Vec<Proposal> {
        let wallet = match self.wallet_get_readonly(&wallet_name) {
            Some(w) => w,
            None => return Vec::new(),
        };
        let start = from.min(wallet.proposal_index);
        let end = (start + limit).min(wallet.proposal_index);
        (start..end)
            .filter_map(|i| self.proposals.get(&proposal_key(&wallet_name, i)))
            .collect()
    }

    /// Get daily spend stats for a wallet
    pub fn get_spend_stats(&self, wallet_name: String) -> serde_json::Value {
        let wallet = match self.wallet_get_readonly(&wallet_name) {
            Some(w) => w,
            None => return serde_json::json!({"error": "ERR_WALLET_NOT_FOUND"}),
        };
        serde_json::json!({
            "daily_limit": wallet.daily_spend_limit.to_string(),
            "daily_used": wallet.daily_spend_used.to_string(),
            "daily_remaining": wallet.daily_spend_limit.saturating_sub(wallet.daily_spend_used).to_string(),
            "reset_at": wallet.daily_spend_reset_at.to_string(),
            "call_max_deposit": wallet.call_max_deposit.to_string(),
        })
    }

    // ── Wallet Configuration (Owner Only) ────────────────────────────

    /// Set Call intent receiver allowlist. Empty = all allowed.
    pub fn set_call_allowed_receivers(
        &mut self,
        wallet_name: String,
        receivers: Vec<AccountId>,
        signature: String,
        expires_at: u64,
    ) {
        self.assert_not_paused();
        self.verify_owner(&format!("set_call_receivers:{}", wallet_name), &signature, expires_at);
        let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        wallet.call_allowed_receivers = receivers;
        self.wallet_insert(&wallet_name, &wallet);
        self.emit_event("call_receivers_updated", serde_json::json!({"wallet": wallet_name}));
        log!("Call receiver allowlist updated for '{}'", wallet_name);
    }

    /// Set max deposit per Call intent (0 = no limit)
    pub fn set_call_max_deposit(
        &mut self,
        wallet_name: String,
        max_deposit: U128,
        signature: String,
        expires_at: u64,
    ) {
        self.assert_not_paused();
        self.verify_owner(&format!("set_call_max_deposit:{}", wallet_name), &signature, expires_at);
        let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        wallet.call_max_deposit = max_deposit.0;
        self.wallet_insert(&wallet_name, &wallet);
        self.emit_event("call_max_deposit_updated", serde_json::json!({"wallet": wallet_name, "max": max_deposit.0.to_string()}));
        log!("Call max deposit set to {} for '{}'", max_deposit.0, wallet_name);
    }

    /// Set daily spend limit (0 = no limit)
    pub fn set_daily_spend_limit(
        &mut self,
        wallet_name: String,
        limit: U128,
        signature: String,
        expires_at: u64,
    ) {
        self.assert_not_paused();
        self.verify_owner(&format!("set_daily_limit:{}", wallet_name), &signature, expires_at);
        let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        wallet.daily_spend_limit = limit.0;
        self.wallet_insert(&wallet_name, &wallet);
        self.emit_event("daily_limit_updated", serde_json::json!({"wallet": wallet_name, "limit": limit.0.to_string()}));
        log!("Daily spend limit set to {} for '{}'", limit.0, wallet_name);
    }

    /// Set relayer fee (charged from wallet storage deposit per execution)
    pub fn set_relayer_fee(
        &mut self,
        wallet_name: String,
        fee: U128,
        signature: String,
        expires_at: u64,
    ) {
        self.assert_not_paused();
        self.verify_owner(&format!("set_relayer_fee:{}", wallet_name), &signature, expires_at);
        let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        wallet.relayer_fee = fee.0;
        self.wallet_insert(&wallet_name, &wallet);
        self.emit_event("relayer_fee_updated", serde_json::json!({"wallet": wallet_name, "fee": fee.0.to_string()}));
        log!("Relayer fee set to {} for '{}'", fee.0, wallet_name);
    }

    /// Set allowed relayers (empty = anyone can relay)
    pub fn set_allowed_relayers(
        &mut self,
        wallet_name: String,
        relayers: Vec<AccountId>,
        signature: String,
        expires_at: u64,
    ) {
        self.assert_not_paused();
        self.verify_owner(&format!("set_relayers:{}", wallet_name), &signature, expires_at);
        let mut wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        wallet.allowed_relayers = relayers;
        self.wallet_insert(&wallet_name, &wallet);
        self.emit_event("relayers_updated", serde_json::json!({"wallet": wallet_name}));
        log!("Relayer allowlist updated for '{}'", wallet_name);
    }

    // ── Intent Activation ─────────────────────────────────────────────

    /// Activate an intent (undo deactivation)
    pub fn activate_intent(
        &mut self,
        wallet_name: String,
        intent_index: u32,
        signature: String,
        expires_at: u64,
    ) {
        self.assert_not_paused();
        self.verify_owner(&format!("activate_intent:{}:{}", wallet_name, intent_index), &signature, expires_at);
        let ikey = intent_key(&wallet_name, intent_index);
        let mut intent = self.intents.get(&ikey).expect("ERR_INTENT_NOT_FOUND");
        intent.active = true;
        self.intents.insert(&ikey, &intent);
        self.emit_event("intent_activated", serde_json::json!({"wallet": wallet_name, "intent_index": intent_index}));
        log!("Intent #{} activated in wallet '{}'", intent_index, wallet_name);
    }

    /// Deactivate an intent (pause without removing)
    pub fn deactivate_intent(
        &mut self,
        wallet_name: String,
        intent_index: u32,
        signature: String,
        expires_at: u64,
    ) {
        self.assert_not_paused();
        self.verify_owner(&format!("deactivate_intent:{}:{}", wallet_name, intent_index), &signature, expires_at);
        let ikey = intent_key(&wallet_name, intent_index);
        let mut intent = self.intents.get(&ikey).expect("ERR_INTENT_NOT_FOUND");
        assert!(intent.active_proposal_count == 0, "ERR_HAS_ACTIVE_PROPOSALS");
        intent.active = false;
        self.intents.insert(&ikey, &intent);
        self.emit_event("intent_deactivated", serde_json::json!({"wallet": wallet_name, "intent_index": intent_index}));
        log!("Intent #{} deactivated in wallet '{}'", intent_index, wallet_name);
    }

    // ── Batch Execution ───────────────────────────────────────────────

    /// Execute multiple approved proposals in a single transaction.
    /// Owner signs once with the batch proposal IDs.
    #[payable]
    pub fn batch_execute(
        &mut self,
        wallet_name: String,
        proposal_ids: Vec<u64>,
        signature: String,
        expires_at: u64,
    ) {
        self.assert_not_paused();
        let action = format!("batch:{}:{:?}", wallet_name, &proposal_ids);
        self.verify_owner(&action, &signature, expires_at);

        assert!(!proposal_ids.is_empty(), "ERR_EMPTY_BATCH");
        assert!(proposal_ids.len() <= 10, "ERR_BATCH_TOO_LARGE: max 10");

        // Pre-validate all proposals before executing any
        for &proposal_id in &proposal_ids {
            let pkey = proposal_key(&wallet_name, proposal_id);
            let proposal = self.proposals.get(&pkey).expect("ERR_PROPOSAL_NOT_FOUND");
            assert!(proposal.status == ProposalStatus::Approved, "ERR_BATCH_NOT_APPROVED: proposal {}", proposal_id);
        }

        let mut executed = 0u32;
        let mut failed = Vec::new();
        for &proposal_id in &proposal_ids {
            let pkey = proposal_key(&wallet_name, proposal_id);
            // Re-check status (previous execution may have side effects)
            if let Some(proposal) = self.proposals.get(&pkey) {
                if proposal.status == ProposalStatus::Approved {
                    self.execute_proposal(&wallet_name, proposal_id);
                    executed += 1;
                } else {
                    failed.push(proposal_id);
                }
            } else {
                failed.push(proposal_id);
            }
        }

        self.emit_event("batch_executed", serde_json::json!({
            "wallet": wallet_name,
            "requested": proposal_ids.len(),
            "executed": executed,
            "failed": failed,
        }));
        log!("Batch executed {}/{} proposals in wallet '{}'", executed, proposal_ids.len(), wallet_name);
    }

    // ── Auto Cleanup ──────────────────────────────────────────────────

    /// Clean up expired proposals to reclaim storage.
    /// Can be called by anyone (not just owner) since it only removes expired proposals.
    /// Reward: caller gets a small storage refund incentive.
    pub fn cleanup_expired(
        &mut self,
        wallet_name: String,
        from_id: u64,
        to_id: u64,
    ) -> u64 {
        self.assert_not_paused();
        let wallet = self.wallet_get_readonly(&wallet_name).expect("ERR_WALLET_NOT_FOUND");
        let now = env::block_timestamp();
        let mut cleaned = 0u64;

        for id in from_id..=to_id.min(wallet.proposal_index.saturating_sub(1)) {
            let pkey = proposal_key(&wallet_name, id);
            if let Some(proposal) = self.proposals.get(&pkey) {
                if (proposal.status == ProposalStatus::Executed ||
                    proposal.status == ProposalStatus::Cancelled) ||
                    (proposal.status == ProposalStatus::Active && proposal.expires_at < now) {
                    // Expired active proposals: cancel them first
                    if proposal.status == ProposalStatus::Active {
                        let ikey = intent_key(&wallet_name, proposal.intent_index);
                        if let Some(mut intent) = self.intents.get(&ikey) {
                            intent.active_proposal_count = intent.active_proposal_count.saturating_sub(1);
                            self.intents.insert(&ikey, &intent);
                        }
                    }
                    self.proposals.remove(&pkey);
                    cleaned += 1;
                }
            }
        }

        if cleaned > 0 {
            self.emit_event("cleanup", serde_json::json!({
                "wallet": wallet_name, "cleaned": cleaned, "from": from_id, "to": to_id,
            }));
            log!("Cleaned up {} expired proposals from wallet '{}'", cleaned, wallet_name);
        }

        cleaned
    }
}

// ── Private Helpers ────────────────────────────────────────────────────────

impl Contract {
    // ── Execution Helpers ─────────────────────────────────────────────

    fn execute_deposit(&mut self, wallet_name: &String) {
        let deposit_amount = env::attached_deposit().as_yoctonear();
        if deposit_amount > 0 {
            self.credit_near(wallet_name, deposit_amount);
        }
        log!("Deposited {} yoctoNEAR to wallet '{}'", deposit_amount, wallet_name);
    }

    fn execute_transfer(&mut self, wallet_name: &String, params: &serde_json::Value) {
        self.assert_not_locked();
        let amount_str = params["amount"].as_str()
            .map(String::from)
            .or_else(|| params["amount"].as_u64().map(|v| v.to_string()))
            .unwrap_or_default();
        let recipient: AccountId = params["recipient"].as_str().expect("ERR_MISSING_RECIPIENT")
            .parse().expect("ERR_INVALID_RECIPIENT");
        let amount: u128 = amount_str.parse().expect("ERR_INVALID_AMOUNT");

        // Enforce daily spend limit
        {
            let mut wallet = self.wallet_get(wallet_name).expect("ERR_WALLET_NOT_FOUND");
            wallet.enforce_spend_limit(env::block_timestamp());
            wallet.track_spend(amount);
            self.wallet_insert(wallet_name, &wallet);
        }

        if let Some(token_str) = params.get("token").and_then(|v| v.as_str()) {
            self.debit_ft(wallet_name, token_str, amount);
            // FT transfer: call ft_transfer on the token contract
            let token_account: AccountId = token_str.parse().expect("ERR_INVALID_TOKEN_ACCOUNT");
            self.locked = true;
            let promise = Promise::new(token_account.clone()).function_call(
                "ft_transfer".to_string(),
                safe_json_ft_transfer(recipient.as_str(), &amount.to_string()),
                NearToken::from_yoctonear(1), // 1 yocto for ft_transfer
                near_sdk::Gas::from_tgas(30),
            );
            // Callback to handle result
            let current_account = env::current_account_id();
            promise.then(Promise::new(current_account).function_call(
                "on_ft_transfer_result".to_string(),
                serde_json::to_vec(&serde_json::json!({
                    "wallet_name": wallet_name,
                    "token": token_account.to_string(),
                    "amount": amount.to_string(),
                    "recipient": recipient.to_string(),
                })).unwrap(),
                NearToken::from_yoctonear(0),
                near_sdk::Gas::from_tgas(5),
            ));
            log!("FT transfer: {} of {} to {} (debit recorded)", amount, token_str, recipient);
        } else {
            self.debit_near(wallet_name, amount);
            Promise::new(recipient.clone()).transfer(NearToken::from_yoctonear(amount));
            log!("Transferred {} yoctoNEAR to {}", amount, recipient);
        }
    }

    fn execute_call(&mut self, wallet_name: &String, params: &serde_json::Value) {
        self.assert_not_locked();
        let receiver_id: AccountId = params["receiver_id"]
            .as_str().expect("ERR_MISSING_RECEIVER_ID")
            .parse().expect("ERR_INVALID_RECEIVER_ID");
        let method_name = params["method_name"]
            .as_str().expect("ERR_MISSING_METHOD_NAME").to_string();
        let args_b64 = params.get("args")
            .and_then(|v| v.as_str()).unwrap_or("");
        let args = base64::engine::general_purpose::STANDARD
            .decode(args_b64).unwrap_or_default();
        let deposit: u128 = params.get("deposit")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let gas_tgas: u64 = params.get("gas")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_EXECUTION_GAS_TGAS)
            .min(MAX_EXECUTION_GAS_TGAS);

        // Enforce wallet limits
        {
            let mut wallet = self.wallet_get(wallet_name).expect("ERR_WALLET_NOT_FOUND");

            // Receiver allowlist check
            assert!(
                wallet.is_call_receiver_allowed(&receiver_id),
                "ERR_RECEIVER_NOT_ALLOWED: {} not in allowlist",
                receiver_id
            );

            // Max deposit per call check
            if wallet.call_max_deposit > 0 {
                assert!(
                    deposit <= wallet.call_max_deposit,
                    "ERR_DEPOSIT_EXCEEDS_MAX: {} > {}",
                    deposit, wallet.call_max_deposit
                );
            }

            // Enforce daily spend limit
            wallet.enforce_spend_limit(env::block_timestamp());
            if deposit > 0 {
                wallet.track_spend(deposit);
            }

            // Charge relayer fee (to wallet's storage deposit)
            if wallet.relayer_fee > 0 {
                wallet.storage_deposit = wallet.storage_deposit.saturating_sub(wallet.relayer_fee);
            }

            self.wallet_insert(wallet_name, &wallet);
        }

        // Debit wallet's internal balance for the deposit
        if deposit > 0 {
            self.debit_near(wallet_name, deposit);
        }

        // Execute cross-contract call with callback to handle result
        self.locked = true;
        let prepaid_gas = near_sdk::Gas::from_tgas(gas_tgas);
        let promise = Promise::new(receiver_id.clone()).function_call(
            method_name.clone(),
            args,
            NearToken::from_yoctonear(deposit),
            prepaid_gas,
        );

        // Callback to self to handle result
        let callback_gas = near_sdk::Gas::from_tgas(5);
        let current_account = env::current_account_id();
        promise.then(Promise::new(current_account).function_call(
            "on_call_result".to_string(),
            serde_json::to_vec(&serde_json::json!({
                "wallet_name": wallet_name,
                "receiver_id": receiver_id.to_string(),
                "method_name": method_name,
                "deposit": deposit.to_string(),
            })).unwrap(),
            NearToken::from_yoctonear(0),
            callback_gas,
        ));

        log!("Called {}.{} with {} yoctoNEAR deposit, {} Tgas", receiver_id, method_name, deposit, gas_tgas);
    }

    /// Callback after cross-contract call completes.
    /// If the call failed, refund the deposit back to the wallet.
    /// Only callable by the contract itself (callback).
    pub fn on_call_result(
        &mut self,
        wallet_name: String,
        receiver_id: AccountId,
        method_name: String,
        deposit: u128,
    ) {
        // Only allow self-calls (callback from our own promise)
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "ERR_CALLBACK_ONLY"
        );
        self.locked = false;
        // Check if the promise succeeded
        let result = env::promise_result(0u64);
        match result {
            PromiseResult::Successful(data) => {
                let data_str = if data.is_empty() {
                    "(empty)".to_string()
                } else {
                    format!("{} bytes", data.len())
                };
                log!("Call {}.{} succeeded: {}", receiver_id, method_name, data_str);
            }
            PromiseResult::Failed => {
                // Refund the deposit on failure
                if deposit > 0 {
                    self.credit_near(&wallet_name, deposit);
                    log!("Call {}.{} FAILED — refunded {} yoctoNEAR to wallet '{}'", receiver_id, method_name, deposit, wallet_name);
                } else {
                    log!("Call {}.{} FAILED (no deposit to refund)", receiver_id, method_name);
                }
                self.emit_event("call_failed", serde_json::json!({
                    "wallet": wallet_name, "receiver": receiver_id, "method": method_name, "refund": deposit,
                }));
            }
        }
    }

    /// Callback after FT transfer. Refunds debit on failure.
    /// Only callable by the contract itself (callback).
    pub fn on_ft_transfer_result(
        &mut self,
        wallet_name: String,
        token: AccountId,
        amount: u128,
        recipient: String,
    ) {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "ERR_CALLBACK_ONLY"
        );
        self.locked = false;
        let result = env::promise_result(0u64);
        match result {
            PromiseResult::Successful(_) => {
                log!("FT transfer {} of {} to {} succeeded", amount, token, recipient);
            }
            PromiseResult::Failed => {
                // Refund the FT debit on failure
                self.credit_ft(&wallet_name, token.as_str(), amount);
                log!("FT transfer {} of {} to {} FAILED — refunded to wallet '{}'", amount, token, recipient, wallet_name);
                self.emit_event("ft_transfer_failed", serde_json::json!({
                    "wallet": wallet_name, "token": token.to_string(), "amount": amount.to_string(), "recipient": recipient,
                }));
            }
        }
    }

    fn emit_event(&mut self, event: &str, data: serde_json::Value) {
        self.event_nonce += 1;
        let mut enriched = data;
        // Inject standard fields for indexer convenience
        if let Some(obj) = enriched.as_object_mut() {
            obj.insert("event_nonce".to_string(), serde_json::json!(self.event_nonce));
            obj.insert("block_height".to_string(), serde_json::json!(env::block_height()));
            obj.insert("block_ts".to_string(), serde_json::json!(env::block_timestamp()));
        }
        env::log_str(&format!(
            "EVENT_JSON:{}",
            serde_json::json!({
                "standard": "clear-msig",
                "version": "1.0.0",
                "event": event,
                "nonce": self.event_nonce,
                "data": enriched,
            })
        ));
    }

    /// Shared logic for approve and cancel_vote to avoid duplication.
    /// Shared logic for nostr schnorr approve and cancel_vote.
    fn verify_nostr_approver(
        &mut self,
        wallet_name: String,
        proposal_id: u64,
        approver_index: u16,
        pubkey_hex: String,
        signature: String,
        expires_at: u64,
        action: &str,
    ) {
        let pkey = proposal_key(&wallet_name, proposal_id);
        let mut proposal = self.proposals.get(&pkey).expect("ERR_PROPOSAL_NOT_FOUND");

        assert!(proposal.status == ProposalStatus::Active, "ERR_NOT_ACTIVE");
        assert!(proposal.expires_at > env::block_timestamp(), "ERR_PROPOSAL_EXPIRED");
        assert!(expires_at > env::block_timestamp(), "ERR_SIG_EXPIRED");

        let ikey = intent_key(&wallet_name, proposal.intent_index);
        let intent = self.intents.get(&ikey).expect("ERR_INTENT_NOT_FOUND");
        assert!((approver_index as usize) < intent.nostr_approvers.len(), "ERR_INVALID_NOSTR_APPROVER_INDEX");

        // Verify the pubkey matches the slot
        let expected_pk = &intent.nostr_approvers[approver_index as usize];
        assert_eq!(pubkey_hex, *expected_pk, "ERR_NOSTR_PK_MISMATCH");

        // Build message and verify schnorr signature
        let params: serde_json::Value = serde_json::from_str(&proposal.param_values).unwrap_or_default();
        let msg = message::build_message(&wallet_name, proposal_id, expires_at, action, &intent, &params);

        message::verify_schnorr_signature(&pubkey_hex, &signature, &msg);

        match action {
            "approve" => {
                assert!(!proposal.has_nostr_approved(approver_index as usize), "ERR_NOSTR_ALREADY_APPROVED");
                proposal.set_nostr_approval(approver_index as usize);

                if proposal.approval_count() >= intent.approval_threshold as u32 {
                    proposal.status = ProposalStatus::Approved;
                    proposal.approved_at = env::block_timestamp();

                    self.emit_event("proposal_approved", serde_json::json!({
                        "wallet": wallet_name, "proposal_id": proposal_id,
                        "approval_count": proposal.approval_count(),
                        "nostr": true,
                    }));

                    log!("Proposal #{} approved (nostr)", proposal_id);
                }
            }
            "cancel" => {
                proposal.set_nostr_cancellation(approver_index as usize);

                if proposal.cancellation_count() >= intent.cancellation_threshold as u32 {
                    proposal.status = ProposalStatus::Cancelled;
                    let mut intent_mut = intent.clone();
                    intent_mut.active_proposal_count = intent_mut.active_proposal_count.saturating_sub(1);
                    self.intents.insert(&ikey, &intent_mut);

                    self.emit_event("proposal_cancelled", serde_json::json!({
                        "wallet": wallet_name, "proposal_id": proposal_id,
                        "cancellation_count": proposal.cancellation_count(),
                        "nostr": true,
                    }));
                }
            }
            _ => env::panic_str("ERR_INVALID_ACTION"),
        }

        self.proposals.insert(&pkey, &proposal);
    }

    fn create_meta_intents(&mut self, name: &str, owner: &AccountId) {
        let owner_npub = self.owner_npub.clone();
        let make = |index: u32, itype: IntentType, iname: &str, template: &str, params: Vec<ParamDef>| Intent {
            wallet_name: name.to_string(),
            index,
            intent_type: itype,
            name: iname.to_string(),
            template: template.to_string(),
            proposers: vec![owner.clone()],
            approvers: vec![owner.clone()],
            nostr_approvers: vec![owner_npub.clone()],
            approval_threshold: 1,
            cancellation_threshold: 1,
            timelock_seconds: 0,
            params,
            execution_gas_tgas: DEFAULT_EXECUTION_GAS_TGAS,
            active: true,
            active_proposal_count: 0,
        };

        self.intents.insert(&intent_key(name, 0), &make(
            0, IntentType::AddIntent, "AddIntent", "add intent definition_hash: {hash}",
            vec![ParamDef { name: "hash".to_string(), param_type: ParamType::String, max_value: None }],
        ));
        self.intents.insert(&intent_key(name, 1), &make(
            1, IntentType::RemoveIntent, "RemoveIntent", "remove intent {index}",
            vec![ParamDef { name: "index".to_string(), param_type: ParamType::U64, max_value: None }],
        ));
        self.intents.insert(&intent_key(name, 2), &make(
            2, IntentType::UpdateIntent, "UpdateIntent", "update intent {index}",
            vec![ParamDef { name: "index".to_string(), param_type: ParamType::U64, max_value: None }],
        ));
    }

    fn validate_params(&self, intent: &Intent, params: &serde_json::Value) {
        for pd in &intent.params {
            match params.get(&pd.name) {
                None => env::panic_str(&format!("ERR_MISSING_PARAM: {}", pd.name)),
                Some(val) => match pd.param_type {
                    ParamType::AccountId => {
                        let s = val.as_str().unwrap_or_else(|| env::panic_str(&format!("ERR_EXPECTED_STRING: {}", pd.name)));
                        s.parse::<AccountId>().unwrap_or_else(|_| env::panic_str(&format!("ERR_INVALID_ACCOUNT: {}", pd.name)));
                    }
                    ParamType::U64 => {
                        let v = val.as_u64()
                            .or_else(|| val.as_str().and_then(|s| s.parse::<u64>().ok()))
                            .unwrap_or_else(|| env::panic_str(&format!("ERR_EXPECTED_U64: {}", pd.name)));
                        if let Some(max) = &pd.max_value {
                            assert!((v as u128) <= max.0, "ERR_EXCEEDS_MAX: {}", pd.name);
                        }
                    }
                    ParamType::U128 => {
                        let s = match val {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Number(n) => n.to_string(),
                            _ => env::panic_str(&format!("ERR_EXPECTED_U128: {}", pd.name)),
                        };
                        let v: u128 = s.parse().unwrap_or_else(|_| env::panic_str(&format!("ERR_INVALID_U128: {}", pd.name)));
                        if let Some(max) = &pd.max_value {
                            assert!(v <= max.0, "ERR_EXCEEDS_MAX: {}", pd.name);
                        }
                    }
                    ParamType::String => {
                        val.as_str().unwrap_or_else(|| env::panic_str(&format!("ERR_EXPECTED_STRING: {}", pd.name)));
                    }
                    ParamType::Bool => {
                        val.as_bool().unwrap_or_else(|| env::panic_str(&format!("ERR_EXPECTED_BOOL: {}", pd.name)));
                    }
                },
            }
        }
    }
}

#[cfg(test)]
// mod verification;
#[cfg(test)]
// mod integration_tests;
#[cfg(test)]
// mod vm_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_template() {
        let intent = Intent {
            wallet_name: "test".to_string(),
            index: 3,
            intent_type: IntentType::Custom,
            name: "Transfer NEAR".to_string(),
            template: "transfer {amount} yoctoNEAR to {recipient}".to_string(),
            proposers: vec![],
            approvers: vec![],
            nostr_approvers: vec![],
            approval_threshold: 1,
            cancellation_threshold: 1,
            timelock_seconds: 0,
            params: vec![
                ParamDef { name: "amount".to_string(), param_type: ParamType::U128, max_value: None },
                ParamDef { name: "recipient".to_string(), param_type: ParamType::AccountId, max_value: None },
            ],
            execution_gas_tgas: 50,
            active: true,
            active_proposal_count: 0,
        };

        let params = serde_json::json!({
            "amount": "1000000000000000000000000",
            "recipient": "bob.near"
        });

        assert_eq!(
            intent.render_template(&params),
            "transfer 1000000000000000000000000 yoctoNEAR to bob.near"
        );
    }

    #[test]
    fn test_proposal_bitmap() {
        let mut p = Proposal {
            id: 0, wallet_name: "w".to_string(), intent_index: 0,
            proposer: "alice.near".parse().unwrap(), status: ProposalStatus::Active,
            proposed_at: 0, approved_at: 0, expires_at: 0,
            approval_bitmap: 0, cancellation_bitmap: 0,
            nostr_approval_bitmap: 0, nostr_cancellation_bitmap: 0,
            param_values: "{}".to_string(), message: "".to_string(),
            intent_params_hash: "".to_string(),
        };

        assert_eq!(p.approval_count(), 0);
        assert!(!p.has_approved(0));

        p.set_approval(0);
        assert!(p.has_approved(0));
        assert_eq!(p.approval_count(), 1);

        p.set_cancellation(0);
        assert!(!p.has_approved(0)); // cancelled clears approval
        assert_eq!(p.cancellation_count(), 1);

        p.reset_votes();
        assert_eq!(p.approval_count(), 0);
        assert_eq!(p.cancellation_count(), 0);
    }

    #[test]
    fn test_template_injection_blocked() {
        let intent = Intent {
            wallet_name: "test".to_string(),
            index: 0,
            intent_type: IntentType::Custom,
            name: "test".to_string(),
            template: "do {param}".to_string(),
            proposers: vec![], approvers: vec![], nostr_approvers: vec![],
            approval_threshold: 1, cancellation_threshold: 1,
            timelock_seconds: 0,
            params: vec![ParamDef { name: "param".to_string(), param_type: ParamType::String, max_value: None }],
            execution_gas_tgas: 50,
            active: true,
            active_proposal_count: 0,
        };

        // Pipe should be rejected
        let params = serde_json::json!({ "param": "evil | wallet: fake" });
        let result = std::panic::catch_unwind(|| intent.render_template(&params));
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_json_ft_transfer() {
        let json = safe_json_ft_transfer("bob.near", "1000000");
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed["receiver_id"], "bob.near");
        assert_eq!(parsed["amount"], "1000000");
        assert_eq!(parsed["msg"], "");
    }
}

