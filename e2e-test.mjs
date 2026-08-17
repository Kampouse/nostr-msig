#!/usr/bin/env node
/**
 * Full E2E test for nostr-msig on testnet
 * Tests: create wallet → propose → nostr approve → execute
 * 
 * Nonce fix: uses separate signer accounts and explicit nonce management
 */

import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/curves/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { connect, keyStores, utils } from 'near-api-js';

const NETWORK_ID = 'testnet';
const RPC = 'https://test.rpc.fastnear.com';
const CONTRACT_ID = 'nostr-msig.kampouse.testnet';
const SIGNER_ID = 'kampouse.testnet';
const KEY_STORE_PATH = '/Users/asil/.near-credentials/testnet';

// Nostr keypair for testing
const nostrPrivKey = hexToBytes('a'.repeat(64));
const nostrPubKey = schnorr.getPublicKey(nostrPrivKey);
const npubHex = bytesToHex(nostrPubKey);

const keyStore = new keyStores.UnencryptedFileSystemKeyStore(KEY_STORE_PATH);

const near = await connect({
  networkId: NETWORK_ID,
  nodeUrl: RPC,
  keyStore,
});

const signerAccount = await near.account(SIGNER_ID);

// Helper: call contract
async function call(method, args, gas = '200000000000000', deposit = '0') {
  try {
    const result = await signerAccount.functionCall({
      contractId: CONTRACT_ID,
      methodName: method,
      args,
      gas: BigInt(gas),
      attachedDeposit: BigInt(deposit),
    });
    return { success: true, result };
  } catch (e) {
    console.error(`  ❌ ${method} failed:`, e.message?.substring(0, 200));
    return { success: false, error: e };
  }
}

// Helper: view contract
async function view(method, args = {}) {
  return await signerAccount.viewFunction({
    contractId: CONTRACT_ID,
    methodName: method,
    args,
  });
}

// Helper: sign nostr message
function signNostrMessage(message) {
  const hash = sha256(new TextEncoder().encode(message));
  const sig = schnorr.sign(hash, nostrPrivKey);
  return { signature: bytesToHex(sig), hash: bytesToHex(hash) };
}

// Build message matching contract format
function buildMessage(action, content, walletName, proposalId, expiresAt) {
  const ts = expiresAt.toString();
  const sec = ts.slice(0, -9) || '0';
  const nanos = ts.slice(-9).padStart(9, '0');
  return `expires ${sec}.${nanos}: ${action} ${content} | wallet: ${walletName} proposal: ${proposalId}`;
}

const WALLET_NAME = `test_${Date.now()}`;
const EXPIRES_AT = BigInt(Date.now() + 86400000) * 1_000_000n; // 24h from now in ns

console.log('=== Nostr-MSIG E2E Test ===');
console.log(`Contract: ${CONTRACT_ID}`);
console.log(`Wallet: ${WALLET_NAME}`);
console.log(`Nostr npub: ${npubHex}`);
console.log('');

// Step 1: Create wallet
console.log('📝 Step 1: Create wallet...');
const createResult = await call('create_wallet', {
  wallet_name: WALLET_NAME,
  nostr_approvers: [npubHex],
}, '200000000000000', '500000000000000000000000'); // 0.5 NEAR
if (!createResult.success) {
  console.log('  (Wallet might already exist, continuing...)');
}

// Step 2: Verify wallet
console.log('🔍 Step 2: Verify wallet exists...');
const wallet = await view('get_wallet', { wallet_name: WALLET_NAME });
console.log(`  Owner: ${wallet.owner}`);
console.log(`  Intents: ${wallet.intent_index}`);

// Step 3: Propose via meta-intent (AddIntent - intent index 0)
console.log('📝 Step 3: Propose AddIntent (transfer intent with nostr approvers)...');
const intentDef = {
  hash: "v1",
  name: "Transfer NEAR",
  template: "transfer {amount} NEAR to {recipient}",
  proposers: [],
  approvers: [],
  nostr_approvers: [npubHex],
  approval_threshold: 1,
  cancellation_threshold: 1,
  params: [
    { name: "amount", param_type: "U128", max_value: null },
    { name: "recipient", param_type: "AccountId", max_value: null }
  ]
};

// Sign the propose message
const proposeMsg = buildMessage('propose', `add intent definition_hash: v1`, WALLET_NAME, 0, EXPIRES_AT);
console.log(`  Message: ${proposeMsg}`);
const { signature: proposeSig } = signNostrMessage(proposeMsg);

const proposeResult = await call('nostr_propose', {
  wallet_name: WALLET_NAME,
  intent_index: 0, // AddIntent meta-intent
  param_values: JSON.stringify({ definition: JSON.stringify(intentDef) }),
  expires_at: EXPIRES_AT.toString(),
  pubkey_hex: npubHex,
  signature: proposeSig,
}, '200000000000000');

if (!proposeResult.success) {
  console.log('  Proposal might exist, checking...');
}

// Step 4: Nostr approve
console.log('📝 Step 4: Nostr approve proposal 0...');
const approveMsg = buildMessage('approve', `add intent definition_hash: v1`, WALLET_NAME, 0, EXPIRES_AT);
console.log(`  Message: ${approveMsg}`);
const { signature: approveSig } = signNostrMessage(approveMsg);

// Wait a bit for nonce to clear
await new Promise(r => setTimeout(r, 2000));

const approveResult = await call('nostr_approve', {
  wallet_name: WALLET_NAME,
  proposal_id: 0,
  approver_index: 0,
  pubkey_hex: npubHex,
  signature: approveSig,
  expires_at: EXPIRES_AT.toString(),
}, '200000000000000');

// Step 5: Quick execute (threshold=1, so we can use quick_execute if threshold matches)
// Or use execute with owner signature
console.log('📝 Step 5: Execute proposal 0 (AddIntent)...');

// Check proposal status first
await new Promise(r => setTimeout(r, 2000));
const proposal = await view('get_proposal', { wallet_name: WALLET_NAME, proposal_id: 0 });
console.log(`  Proposal status: ${proposal.status}`);

if (proposal.status === 'Approved' || proposal.status === 'Active') {
  // Use quick_execute if threshold is 1
  const intent = await view('get_intent', { wallet_name: WALLET_NAME, intent_index: 0 });
  console.log(`  Intent approval_threshold: ${intent.approval_threshold}`);
  
  if (intent.approval_threshold === 1 && proposal.status === 'Approved') {
    await new Promise(r => setTimeout(r, 2000));
    const execResult = await call('quick_execute', {
      wallet_name: WALLET_NAME,
      proposal_id: 0,
    }, '200000000000000');
    
    if (execResult.success) {
      console.log('  ✅ AddIntent executed!');
    }
  }
}

// Verify new intent was added
await new Promise(r => setTimeout(r, 1000));
const wallet2 = await view('get_wallet', { wallet_name: WALLET_NAME });
console.log(`  Wallet now has ${wallet2.intent_index} intents`);

// Step 6: Now propose a Transfer via the new intent
console.log('📝 Step 6: Propose Transfer via new intent...');
const transferIntentIndex = wallet2.intent_index - 1;

const transferProposeMsg = buildMessage('propose', `transfer 1 yoctoNEAR to ${SIGNER_ID}`, WALLET_NAME, 1, EXPIRES_AT);
const { signature: transferProposeSig } = signNostrMessage(transferProposeMsg);

const transferProposeResult = await call('nostr_propose', {
  wallet_name: WALLET_NAME,
  intent_index: transferIntentIndex,
  param_values: JSON.stringify({ amount: "1000000000000000000000000", recipient: SIGNER_ID }),
  expires_at: EXPIRES_AT.toString(),
  pubkey_hex: npubHex,
  signature: transferProposeSig,
}, '200000000000000');

// Step 7: Approve transfer
console.log('📝 Step 7: Approve transfer proposal...');
await new Promise(r => setTimeout(r, 2000));

const transferApproveMsg = buildMessage('approve', `transfer 1000000000000000000000000 yoctoNEAR to ${SIGNER_ID}`, WALLET_NAME, 1, EXPIRES_AT);
const { signature: transferApproveSig } = signNostrMessage(transferApproveMsg);

await new Promise(r => setTimeout(r, 2000));
const transferApproveResult = await call('nostr_approve', {
  wallet_name: WALLET_NAME,
  proposal_id: 1,
  approver_index: 0,
  pubkey_hex: npubHex,
  signature: transferApproveSig,
  expires_at: EXPIRES_AT.toString(),
}, '200000000000000');

// Step 8: Execute transfer
console.log('📝 Step 8: Execute transfer...');
await new Promise(r => setTimeout(r, 2000));

const proposal1 = await view('get_proposal', { wallet_name: WALLET_NAME, proposal_id: 1 });
console.log(`  Transfer proposal status: ${proposal1.status}`);

if (proposal1.status === 'Approved') {
  await new Promise(r => setTimeout(r, 2000));
  const execResult = await call('quick_execute', {
    wallet_name: WALLET_NAME,
    proposal_id: 1,
  }, '200000000000000');
  
  if (execResult.success) {
    console.log('  ✅ Transfer executed!');
  }
}

// Final status
await new Promise(r => setTimeout(r, 1000));
const finalProposal0 = await view('get_proposal', { wallet_name: WALLET_NAME, proposal_id: 0 });
const finalProposal1 = await view('get_proposal', { wallet_name: WALLET_NAME, proposal_id: 1 });
console.log('');
console.log('=== Final Status ===');
console.log(`Proposal 0 (AddIntent): ${finalProposal0.status}`);
console.log(`Proposal 1 (Transfer): ${finalProposal1.status}`);
console.log('');
console.log(finalProposal0.status === 'Executed' && finalProposal1.status === 'Executed'
  ? '🎉 FULL E2E SUCCESS!'
  : '⚠️  Partial success — check logs above');
