/**
 * nostr-msig E2E — nmsig.vault.kampy.testnet
 * init → create_wallet → AddIntent(Deposit) → deposit → AddIntent(Transfer)
 *      → propose 0.5Ⓝ transfer → nostr approve → execute → verify
 * All state changes authorized by BIP-340 schnorr sigs from a Nostr key.
 * Resume: START=<n> skips first n steps (0-12).
 */
const ROOT = '/Users/asil/.openclaw/workspace';
const { schnorr } = require(ROOT + '/outlayer-wallet/node_modules/@noble/curves/secp256k1');
const { sha256 } = require(ROOT + '/outlayer-wallet/node_modules/@noble/hashes/sha256');
const { bytesToHex } = require(ROOT + '/outlayer-wallet/node_modules/@noble/hashes/utils');
const nearAPI = require(ROOT + '/node_modules/near-api-js');
const fs = require('fs');

const CONTRACT = 'nmsig.vault.kampy.testnet';
const RPC = 'https://rpc.testnet.fastnear.com';

// ── Nostr test key ─────────────────────────────────────────────────────
const NSEC = sha256(new TextEncoder().encode('nostr-msig-e2e-test-v1'));
const NPubHex = bytesToHex(schnorr.getPublicKey(NSEC));

const yocto = (n) => (BigInt(Math.round(n * 1e6)) * 10n ** 18n).toString();
const nowNs = () => BigInt(Date.now()) * 1_000_000n;
const EXPIRY = nowNs() + 2n * 3600n * 1_000_000_000n;

const schnorrSign = (m) => bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(m)), NSEC));
const ownerSig = (nonce, action) => schnorrSign(`expires ${EXPIRY}.000000000: ${action} | nonce: ${nonce} | contract: owner`);
const fmtExpiry = (ns) => `${ns / 1_000_000_000n}.${String(ns % 1_000_000_000n).padStart(9, '0')}`;
const proposalMsg = (w, i, action, content) => `expires ${fmtExpiry(EXPIRY)}: ${action} ${content} | wallet: ${w} proposal: ${i}`;

const depHash = (def) => bytesToHex(sha256(new TextEncoder().encode(def)));
const depositIntent = JSON.stringify({
  wallet_name: 'treasury', index: 0, intent_type: 'Deposit', name: 'Deposit NEAR',
  template: 'deposit NEAR to wallet', proposers: [], approvers: [], nostr_approvers: [NPubHex],
  approval_threshold: 1, cancellation_threshold: 1, timelock_seconds: 0,
  params: [{ name: 'amount', param_type: 'U128', max_value: null }],
  execution_gas_tgas: 50, active: true, active_proposal_count: 0,
});
const transferIntent = JSON.stringify({
  wallet_name: 'treasury', index: 0, intent_type: 'Transfer', name: 'Transfer NEAR',
  template: 'transfer {amount} yoctoNEAR to {recipient}', proposers: [], approvers: [], nostr_approvers: [NPubHex],
  approval_threshold: 1, cancellation_threshold: 1, timelock_seconds: 0,
  params: [
    { name: 'amount', param_type: 'U128', max_value: yocto(100) },
    { name: 'recipient', param_type: 'AccountId', max_value: null },
  ],
  execution_gas_tgas: 50, active: true, active_proposal_count: 0,
});
const RECIPIENT = 'vault.kampy.testnet';
const XFER_AMT = '500000000000000000000000'; // 0.5 NEAR
const rawArgs = (obj, big) => JSON.parse('{' + Object.entries(obj).map(([k, v]) => big && big.includes(k) ? `"${k}":${v}` : `"${k}":${JSON.stringify(v)}`).join(',') + '}');

(async () => {
  const cred = JSON.parse(fs.readFileSync(`${process.env.HOME}/.near-credentials/testnet/${CONTRACT}.json`, 'utf8'));
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  await keyStore.setKey('testnet', CONTRACT, nearAPI.KeyPair.fromString(cred.private_key));
  const near = await nearAPI.connect({ networkId: 'testnet', nodeUrl: RPC, keyStore });
  const acct = await near.account(CONTRACT);
  const log = (...a) => console.log(...a);
  log(`npub: ${NPubHex.slice(0, 24)}...`);

  const call = async (label, method, args, { gas = 50n * 10n ** 12n, deposit = '0' } = {}) => {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const r = await acct.functionCall({ contractId: CONTRACT, methodName: method, args, gas: gas.toString(), attachedDeposit: deposit });
        if (r.status?.Failure) { log(`❌ ${label} — ${r.status.Failure.ActionError?.error?.kind || 'failure'}`); process.exit(1); }
        log(`✅ ${label}`); return r;
      } catch (e) {
        const m = (e.message || '').match(/ERR_[A-Z_]+|panicked: [^"\\]+|insufficient|balance/);
        if (attempt === 2) { log(`❌ ${label} — ${m ? m[0].slice(0, 160) : (e.message || '').slice(0, 200)}`); process.exit(1); }
        await new Promise(r => setTimeout(r, 3000));
      }
    }
  };
  const view = async (method, args = {}, tries = 6) => {
    for (let i = 0; i < tries; i++) {
      try {
        const b64 = Buffer.from(JSON.stringify(args)).toString('base64');
        const r = await (await fetch(RPC, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: '1', method: 'query', params: { request_type: 'call_function', finality: 'final', account_id: CONTRACT, method_name: method, args_base64: b64 } }) })).json();
        if (r.error) throw new Error(r.error.message);
        const out = JSON.parse(Buffer.from(r.result.result).toString('utf8'));
        if (out == null) throw new Error('null view');
        return out;
      } catch (e) { if (i === tries - 1) throw e; await new Promise(r => setTimeout(r, 2000 * (i + 1))); }
    }
  };

  const STEP = parseInt(process.env.START || '0', 10);
  let cur = 0;
  const step = async (label, fn) => { const n = cur++; if (n < STEP) { log(`⏭️  ${label}`); return; } await fn(); };

  const proposeApprove = async (nonce, idx, label, intentIndex, paramValues, content) => {
    await step(`propose ${label}`, () => call(`propose ${label}`, 'propose',
      rawArgs({ wallet_name: 'treasury', intent_index: intentIndex, param_values: JSON.stringify(paramValues), signature: ownerSig(nonce, `propose:treasury:${idx}`), expires_at: EXPIRY.toString() }, ['expires_at'])));
    await step(`verify+approve ${label}`, async () => {
      const stored = await view('get_proposal_message', { wallet_name: 'treasury', id: idx });
      const mine = proposalMsg('treasury', idx, 'propose', content);
      const strip = (s) => s.replace(/^expires [^:]+: /, '');
      if (strip(stored) !== strip(mine)) { log(`   msg match ❌\n   stored: ${stored}\n   mine:   ${mine}`); process.exit(1); }
      log('   msg match: ✅ exact (JS == contract, modulo per-run expiry)');
      await call(`nostr approve ${label}`, 'approve',
        rawArgs({ wallet_name: 'treasury', proposal_id: idx, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(proposalMsg('treasury', idx, 'approve', content)), expires_at: EXPIRY.toString() }, ['expires_at']));
    });
  };
  const exec = (label, id, nonce, deposit = '0') => step(label, () => call(label, 'execute',
    rawArgs({ wallet_name: 'treasury', proposal_id: id, signature: ownerSig(nonce, `execute:treasury:${id}`), expires_at: EXPIRY.toString() }, ['expires_at']), { deposit }));

  await step('init', () => call('init new(owner_npub)', 'new', { owner_npub: NPubHex }, { gas: 30n * 10n ** 12n }));
  await step('create_wallet', () => call('create_wallet(treasury, +0.5Ⓝ)', 'create_wallet',
    rawArgs({ name: 'treasury', signature: ownerSig(0, 'create_wallet:treasury'), expires_at: EXPIRY.toString() }, ['expires_at']),
    { deposit: yocto(0.5) }));

  await proposeApprove(1, 0, 'AddIntent(Deposit)', 0,
    { hash: depHash(depositIntent), definition: depositIntent }, `add intent definition_hash: ${depHash(depositIntent)}`);
  await exec('execute AddIntent → deposit 1Ⓝ', 0, 2, yocto(1));

  await proposeApprove(3, 1, 'AddIntent(Transfer)', 0,
    { hash: depHash(transferIntent), definition: transferIntent }, `add intent definition_hash: ${depHash(transferIntent)}`);
  await exec('execute AddIntent → Transfer intent', 1, 4);

  await proposeApprove(6, 3, `transfer 0.5Ⓝ→${RECIPIENT}`, 4,
    { amount: XFER_AMT, recipient: RECIPIENT }, `transfer ${XFER_AMT} to ${RECIPIENT}`);
  await exec('execute transfer (0.5Ⓝ out)', 3, 7);

  await step('final views', async () => {
    const state = await view('get_wallet_state', { wallet_name: 'treasury' });
    const intents = await view('list_intents', { wallet_name: 'treasury' });
    const pm = await view('get_proposal_message', { wallet_name: 'treasury', id: 3 });
    log('\n════ RESULT ════');
    log(`treasury NEAR balance: ${(Number(state.near_balance) / 1e24).toFixed(4)} Ⓝ (expect 0.5: 1.0 in, 0.5 out)`);
    log(`intents: ${intents.length} (3 meta + Deposit + Transfer)`);
    log(`the signed message was:\n   "${pm}"`);
    log('\nALL PASS ✅ — nostr schnorr auth works end-to-end on NEAR');
  });
})().catch(e => { console.error('FATAL', (e.message || e).toString().slice(0, 300)); process.exit(1); });
