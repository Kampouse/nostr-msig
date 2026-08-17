#!/usr/bin/env python3
"""nostr-msig v3 security upgrade patch."""
import re

LIB = 'contract/src/lib.rs'
MSG = 'contract/src/message.rs'
s = open(LIB).read()
orig = s

# ── 1. State struct: owner set + guardian + nonce bitmap ──────────────
s = s.replace(
    """    event_nonce: u64,
    /// Monotonic counter for replay protection. Each owner action increments this.
    owner_nonce: u64,""",
    """    event_nonce: u64,
    /// Window base for owner nonce replay protection.
    owner_nonce: u64,
    /// Bitmap of consumed nonces within [owner_nonce, owner_nonce+64).
    owner_nonce_bitmap: u64,""")

# remove owner_npub single field from struct
s = s.replace(
    """pub struct Contract {
    /// Contract version for migration tracking.
    version: u32,""",
    """pub struct Contract {
    /// Contract version for migration tracking.
    version: u32,
    /// Owner nostr npubs (hex). Any owner key can authorize owner actions.
    owner_npubs: Vec<String>,
    /// Optional guardian npub — may ONLY pause the contract.
    guardian_npub: Option<String>,""")

# find old owner_npub field line in struct and drop it
s = s.replace("    version: u32,\n    owner_npub: String,\n", "    version: u32,\n")

# ── 2. new() ───────────────────────────────────────────────────────────
s = s.replace(
    """    pub fn new(owner_npub: String) -> Self {
        assert!(!owner_npub.is_empty(), "ERR_EMPTY_OWNER_NPUB");
        Self {
            version: 2,
            owner_npub,""",
    """    pub fn new(owner_npubs: Vec<String>) -> Self {
        assert!(!owner_npubs.is_empty(), "ERR_EMPTY_OWNERS");
        assert!(owner_npubs.len() <= 8, "ERR_TOO_MANY_OWNERS: max 8");
        for np in &owner_npubs {
            assert!(np.len() == 64, "ERR_INVALID_NPUB_LEN: expected 64 hex chars");
            assert!(np.chars().all(|c| c.is_ascii_hexdigit()), "ERR_INVALID_NPUB_HEX");
        }
        Self {
            version: 3,
            owner_npubs,
            guardian_npub: None,""")
s = s.replace("""            event_nonce: 0,
            owner_nonce: 0,""",
    """            event_nonce: 0,
            owner_nonce: 0,
            owner_nonce_bitmap: 0,""")

# ── 3. verify_owner rewrite + nonce window ─────────────────────────────
s = s.replace(
    """    /// Verify the caller is the nostr owner via schnorr signature.
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
    }""",
    """    /// Verify the caller is an owner via schnorr signature over
    /// `expires {ts}.000000000: {action} | nonce: {n} | contract: {account_id}`.
    /// Binds the signature to THIS contract account (anti cross-contract replay)
    /// and to a client-chosen nonce inside a 64-slot sliding window (safe for
    /// concurrent relayers).
    fn verify_owner(&mut self, action: &str, signature: &str, expires_at: u64, nonce: u64) {
        assert!(expires_at > env::block_timestamp(), "ERR_SIG_EXPIRED");
        let msg = format!(
            "expires {}.000000000: {} | nonce: {} | contract: {}",
            expires_at, action, nonce, env::current_account_id()
        );
        let valid = self.owner_npubs.iter()
            .any(|pk| message::try_schnorr_verify(pk, signature, &msg));
        assert!(valid, "ERR_INVALID_OWNER_SIGNATURE");
        self.consume_nonce(nonce);
    }

    /// Sliding 64-slot nonce window: any unused nonce in
    /// [owner_nonce, owner_nonce+64) is accepted; the window slides forward
    /// as low nonces are consumed. Prevents both replay and concurrent-tx races.
    fn consume_nonce(&mut self, nonce: u64) {
        assert!(nonce >= self.owner_nonce, "ERR_NONCE_TOO_LOW");
        assert!(nonce < self.owner_nonce + 64, "ERR_NONCE_WINDOW_EXCEEDED");
        let bit = 1u64 << (nonce - self.owner_nonce);
        assert!(self.owner_nonce_bitmap & bit == 0, "ERR_NONCE_ALREADY_USED");
        self.owner_nonce_bitmap |= bit;
        while self.owner_nonce_bitmap & 1 != 0 {
            self.owner_nonce += 1;
            self.owner_nonce_bitmap >>= 1;
        }
    }""")

# ── 4. pause: guardian-aware, no nonce needed (idempotent, expiry-bound) ─
s = s.replace(
    """    /// Emergency pause — blocks all state-changing calls except unpause.
    pub fn pause(&mut self, signature: String, expires_at: u64) {
        self.verify_owner("pause", &signature, expires_at);
        self.paused = true;""",
    """    /// Emergency pause — blocks all state-changing calls except unpause.
    /// Authorized by ANY owner npub OR the guardian npub (guardian can only pause).
    pub fn pause(&mut self, signature: String, expires_at: u64) {
        assert!(expires_at > env::block_timestamp(), "ERR_SIG_EXPIRED");
        let msg = format!(
            "expires {}.000000000: pause | contract: {}",
            expires_at, env::current_account_id()
        );
        let is_owner = self.owner_npubs.iter()
            .any(|pk| message::try_schnorr_verify(pk, &signature, &msg));
        let is_guardian = self.guardian_npub.as_deref()
            .map_or(false, |g| message::try_schnorr_verify(g, &signature, &msg));
        assert!(is_owner || is_guardian, "ERR_NOT_AUTHORIZED_TO_PAUSE");
        self.paused = true;""")

s = s.replace(
    """    pub fn unpause(&mut self, signature: String, expires_at: u64) {
        self.verify_owner("unpause", &signature, expires_at);""",
    """    pub fn unpause(&mut self, signature: String, expires_at: u64, nonce: u64) {
        self.verify_owner("unpause", &signature, expires_at, nonce);""")

# ── 5. rotate_owner_key → owner-set management ──────────────────────────
s = s.replace(
    """    /// Rotate the contract owner's nostr key. Requires signature from the CURRENT nsec.
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
    }""",
    """    /// Add an owner npub (requires an existing owner signature).
    pub fn add_owner_npub(&mut self, new_npub: String, signature: String, expires_at: u64, nonce: u64) {
        assert!(new_npub.len() == 64, "ERR_INVALID_NPUB_LEN: expected 64 hex chars");
        assert!(new_npub.chars().all(|c| c.is_ascii_hexdigit()), "ERR_INVALID_NPUB_HEX");
        self.verify_owner("add_owner_npub", &signature, expires_at, nonce);
        assert!(!self.owner_npubs.contains(&new_npub), "ERR_OWNER_ALREADY_PRESENT");
        assert!(self.owner_npubs.len() < 8, "ERR_TOO_MANY_OWNERS: max 8");
        self.owner_npubs.push(new_npub.clone());
        self.emit_event("owner_added", serde_json::json!({ "new_npub": new_npub }));
        log!("Owner npub added: {}", &new_npub[..16]);
    }

    /// Remove an owner npub. The last owner cannot be removed.
    pub fn remove_owner_npub(&mut self, npub: String, signature: String, expires_at: u64, nonce: u64) {
        self.verify_owner("remove_owner_npub", &signature, expires_at, nonce);
        assert!(self.owner_npubs.len() > 1, "ERR_LAST_OWNER: cannot remove the final owner");
        let before = self.owner_npubs.len();
        self.owner_npubs.retain(|p| p != &npub);
        assert!(self.owner_npubs.len() < before, "ERR_OWNER_NOT_FOUND");
        self.emit_event("owner_removed", serde_json::json!({ "npub": npub }));
        log!("Owner npub removed: {}", &npub[..16]);
    }

    /// Set (or clear with None) the guardian npub. Guardian may ONLY pause.
    pub fn set_guardian(&mut self, npub: Option<String>, signature: String, expires_at: u64, nonce: u64) {
        if let Some(ref n) = npub {
            assert!(n.len() == 64, "ERR_INVALID_NPUB_LEN: expected 64 hex chars");
            assert!(n.chars().all(|c| c.is_ascii_hexdigit()), "ERR_INVALID_NPUB_HEX");
        }
        self.verify_owner("set_guardian", &signature, expires_at, nonce);
        self.guardian_npub = npub.clone();
        self.emit_event("guardian_set", serde_json::json!({ "guardian_npub": npub }));
    }""")

# ── 6. All owner-gated pub fns: add `nonce: u64` param + call-site arg ──
# uniform call-site patch first (pause already handled above)
s = s.replace('self.verify_owner(&format!(", 'self.verify_owner(&format!(')  # no-op safety
s = re.sub(
    r'(self\.verify_owner\((?:"[^"]*"|&format!\([^;]*?\)), &signature, expires_at)\);',
    r'\1, nonce);', s, flags=re.S)

# add nonce param to every pub fn whose body contains verify_owner( — handle
# multi-line signatures ending with `expires_at: u64,\n    ) {`
fn_start = re.compile(r'(pub fn \w+\(\s*(?:&mut self,)?[^)]*?expires_at: u64,)(\s*\)\s*\{)', re.S)

def add_nonce(m):
    return m.group(1) + '\n        nonce: u64,' + m.group(2)

# find all pub fn blocks containing verify_owner
lines = s.split('\n')
out = []
i = 0
while i < len(lines):
    line = lines[i]
    out.append(line)
    if line.strip().startswith('pub fn ') and 'expires_at: u64,' not in line:
        # scan ahead for signature end; find param list termination
        sig_open = '(' in line
        j = i + 1
        sig_lines = [line]
        # collect until we hit ') {' line
        while j < len(lines) and not re.match(r'\s*\) \{', lines[j]):
            sig_lines.append(lines[j]); j += 1
        body_start = j + 1
        # find body end: next line matching '    }' at same indent after body start
        k = body_start
        body = []
        while k < len(lines):
            body.append(lines[k])
            if re.match(r'    \}$', lines[k]):
                break
            k += 1
        block = '\n'.join(sig_lines + [') {'] + body)
        if 'self.verify_owner(' in block:
            # insert nonce into signature (before the ') {' line, after expires_at: u64,)
            sig_text = '\n'.join(sig_lines + [lines[j]])
            if 'nonce: u64' not in sig_text:
                new_sig = sig_text.replace('expires_at: u64,', 'expires_at: u64,\n        nonce: u64,')
                out = out[:-1]  # drop the pub fn line we already added
                out.extend(new_sig.split('\n'))
                out.append('    }' if False else lines[j])  # ') {'
                # append body
                for bl in body:
                    out.append(bl)
                i = k + 1
                continue
    i += 1
s = '\n'.join(out)

# ── 7. remaining owner_npub references ──────────────────────────────────
s = s.replace("        let owner_display = self.owner_npub.clone();", "        let owner_display = self.owner_npubs.first().cloned().unwrap_or_default();")
s = s.replace('"owner_npub": owner_display,', '"owner_npub": owner_display,')
s = s.replace("        let owner_npub = self.owner_npub.clone();", "        let owner_npub = self.owner_npubs.first().cloned().unwrap_or_default();")
s = s.replace("let owner_is_approver = intent.nostr_approvers.iter().any(|p| p == &self.owner_npub);",
              "let owner_is_approver = intent.nostr_approvers.iter().any(|p| self.owner_npubs.contains(p));")

# views
s = s.replace(
    """    /// Get the current owner nonce (for clients to include in signatures)
    pub fn get_owner_nonce(&self) -> u64 {
        self.owner_nonce
    }""",
    """    /// Get the owner nonce window base (for clients to pick a nonce in [base, base+64))
    pub fn get_owner_nonce(&self) -> u64 {
        self.owner_nonce
    }

    /// Get the consumed-nonce bitmap within the current window.
    pub fn get_owner_nonce_bitmap(&self) -> u64 {
        self.owner_nonce_bitmap
    }

    /// Get all owner npubs.
    pub fn get_owner_npubs(&self) -> Vec<String> {
        self.owner_npubs.clone()
    }

    /// Get the guardian npub, if set.
    pub fn get_guardian_npub(&self) -> Option<String> {
        self.guardian_npub.clone()
    }""")

# ── 8. Relayer payout on successful execution ──────────────────────────
s = s.replace(
    """        proposal.status = ProposalStatus::Executed;
        self.proposals.insert(&pkey, &proposal);
        let mut intent_mut = intent.clone();
        intent_mut.active_proposal_count = intent_mut.active_proposal_count.saturating_sub(1);
        self.intents.insert(&ikey, &intent_mut);
        self.emit_event("proposal_executed", serde_json::json!({
            "wallet": wallet_name, "proposal_id": proposal_id,
        }));""",
    """        proposal.status = ProposalStatus::Executed;
        self.proposals.insert(&pkey, &proposal);
        let mut intent_mut = intent.clone();
        intent_mut.active_proposal_count = intent_mut.active_proposal_count.saturating_sub(1);
        self.intents.insert(&ikey, &intent_mut);

        // ── Relayer payout: reward the tx submitter from wallet balance ──
        // (gas + service fee). Only if the relayer is allowed and a fee is set.
        let relayer = env::predecessor_account_id();
        if relayer != env::current_account_id() {
            if let Some(mut wallet) = self.wallet_get_readonly(wallet_name) {
                if wallet.is_relayer_allowed(&relayer) && wallet.relayer_fee > 0 {
                    let bal = self.get_wallet_near_balance(wallet_name.clone()).0;
                    let payout = wallet.relayer_fee.min(bal);
                    if payout > 0 {
                        self.debit_near(wallet_name, payout);
                        wallet.storage_used = wallet.storage_used; // no-op keep borrow
                        Promise::new(relayer.clone()).transfer(payout);
                        log!("Relayer fee paid: {} yoctoNEAR to {}", payout, relayer);
                    }
                }
                let _ = &mut wallet;
            }
        }

        self.emit_event("proposal_executed", serde_json::json!({
            "wallet": wallet_name, "proposal_id": proposal_id,
        }));""")

open(LIB, 'w').write(s)

# ── message.rs: try-verify + contract-id binding in build_message ──────
m = open(MSG).read()
m = m.replace(
    """    format!(
        "expires {}: {} {} | wallet: {} proposal: {}",
        expires_display, action, content, wallet_name, proposal_index
    )""",
    """    // Binding the contract account id into the signed message prevents
    // cross-contract / cross-chain replay of approval signatures.
    format!(
        "expires {}: {} {} | wallet: {} proposal: {} | contract: {}",
        expires_display, action, content, wallet_name, proposal_index,
        env::current_account_id()
    )""")

m = m.replace(
    """/// Verify a BIP-340 schnorr signature (used by Nostr).""",
    """/// Non-panicking schnorr verify — returns false instead of panicking.
/// Used for multi-owner key sets where several pubkeys are tried.
pub fn try_schnorr_verify(pubkey_hex: &str, signature_hex: &str, message: &str) -> bool {
    use k256::schnorr::VerifyingKey;
    use k256::sha2::{Sha256, Digest};

    if pubkey_hex.len() != 64 || signature_hex.len() != 64 { return false; }
    if !pubkey_hex.chars().all(|c| c.is_ascii_hexdigit()) { return false; }
    if !signature_hex.chars().all(|c| c.is_ascii_hexdigit()) { return false; }

    let Ok(pk) = VerifyingKey::from_bytes(&hex_decode(pubkey_hex).try_into().unwrap()) else { return false; };
    let Ok(sig) = k256::schnorr::Signature::try_from(&hex_decode(signature_hex)[..]) else { return false; };
    let msg_hash = Sha256::digest(message.as_bytes());
    verifying_key_verify_raw(&pk, &msg_hash, &sig)
}

fn verifying_key_verify_raw(
    vk: &k256::schnorr::VerifyingKey,
    hash: &[u8],
    sig: &k256::schnorr::Signature,
) -> bool {
    use k256::schnorr::VerifyingKey;
    let _ = VerifyingKey::from_bytes;
    vk.verify_raw(hash.into(), sig).is_ok()
}

/// Verify a BIP-340 schnorr signature (used by Nostr).""")

open(MSG, 'w').write(m)
print("patched lib.rs and message.rs")
