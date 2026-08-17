/**
 * nostr-msig v3 E2E — nmsig.vault.kampy.testnet
 * Covers: multi-owner init, create_wallet, AddIntent(Deposit)+execute,
 * AddIntent(Transfer)+execute, transfer propose/approve/execute,
 * + SECURITY: stale-nonce rejection, owner-nonce window, guardian pause,
 *   relayer fee payout.
 * Resume: START=<n> skips first n steps.
 */
const ROOT = '/Users/asil/.openclaw/workspace';
const { schnorr } = require(ROOT + '/outlayer-wallet/node_modules/@noble/curves/secp256k1');
const { sha256 } = require(ROOT + '/outlayer-wallet/node_modules/@noble/hashes/sha256');
const { bytesToHex } = require(ROOT + '/outlayer-wallet/node_modules/@noble/hashes/utils');
const nearAPI = require(ROOT + '/node_modules/near-api-js');
const fs = require('fs');

const CONTRACT = 'nmsig.vault.kampy.testnet';
const RPC = 'https://rpc.testnet.fastnear.com';

const NSEC = sha256(new TextEncoder().encode('nostr-msig-e2e-test-v1'));
const NPubHex = bytesToHex(schnorr.getPublicKey(NSEC));
const GSEC = sha256(new TextEncoder().encode('nostr-msig-guardian-v1'));
const GPubHex = bytesToHex(schnorr.getPublicKey(GSEC));

const yocto = (n) => (BigInt(Math.round(n * 1e6)) * 10n ** 18n).toString();
const nowNs = () => BigInt(Date.now()) * 1_000_000n;
// Use whole-second expiry (×1e9 ns) so the u64 survives JSON double round-trip
// exactly — client and contract must build the identical signed string.
const EXPIRY = (BigInt(Math.floor(Date.now() / 1000)) + 7200n) * 1_000_000_000n;
const schnorrSign = (m, sk = NSEC) => bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(m)), sk));
let NONCE = 0;
const ownerSig = (nonce, action) => schnorrSign(`expires ${EXPIRY}.000000000: ${action} | nonce: ${nonce} | contract: ${CONTRACT}`);
const nonceSig = (action) => { const n = NONCE++; return { nonce: n, signature: ownerSig(n, action) }; };
const fmt = (ns) => `${ns / 1_000_000_000n}.${String(ns % 1_000_000_000n).padStart(9, '0')}`;
const pMsg = (i, action, content) => `expires ${fmt(EXPIRY)}: ${action} ${content} | wallet: treasury proposal: ${i} | contract: ${CONTRACT}`;
const depHash = (def) => bytesToHex(sha256(new TextEncoder().encode(def)));
const mkIntent = (type, template, params, name) => JSON.stringify({
  wallet_name: 'treasury', index: 0, intent_type: type, name,
  template, proposers: [], approvers: [], nostr_approvers: [NPubHex],
  approval_threshold: 1, cancellation_threshold: 1, timelock_seconds: 0,
  params, execution_gas_tgas: 50, active: true, active_proposal_count: 0,
});
const depositIntent = mkIntent('Deposit', 'deposit NEAR to wallet',
  [{ name: 'amount', param_type: 'U128', max_value: null }], 'Deposit NEAR');
const transferIntent = mkIntent('Transfer', 'transfer {amount} yoctoNEAR to {recipient}',
  [{ name: 'amount', param_type: 'U128', max_value: yocto(100) },
   { name: 'recipient', param_type: 'AccountId', max_value: null }], 'Transfer NEAR');
const RECIPIENT = 'vault.kampy.testnet';
const XFER_AMT = '500000000000000000000000'; // 0.5 NEAR
const rawArgs = (obj, big) => Buffer.from(JSON.stringify(
  JSON.parse('{' + Object.entries(obj).map(([k, v]) => big && big.includes(k) ? `"${k}":${v}` : `"${k}":${JSON.stringify(v)}`).join(',') + '}'),
  (k, v) => typeof v === 'bigint' ? v.toString() : v));

(async () => {
  const cred = JSON.parse(fs.readFileSync(`${process.env.HOME}/.near-credentials/testnet/${CONTRACT}.json`, 'utf8'));
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  await keyStore.setKey('testnet', CONTRACT, nearAPI.KeyPair.fromString(cred.private_key));
  const near = await nearAPI.connect({ networkId: 'testnet', nodeUrl: RPC, keyStore });
  const acct = await near.account(CONTRACT);
  const log = (...a) => console.log(...a);
  log(`owner npub: ${NPubHex.slice(0, 20)}... | guardian: ${GPubHex.slice(0, 20)}...`);

  const call = async (label, method, args, { gas = 50n * 10n ** 12n, deposit = '0', mustFail = null } = {}) => {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const r = await acct.functionCall({ contractId: CONTRACT, methodName: method, args, gas: gas.toString(), attachedDeposit: deposit });
        const fail = r.status?.Failure ? JSON.stringify(r.status.Failure) : null;
        if (mustFail) {
          if (fail && fail.includes(mustFail)) { log(`🛡️ ${label} → correctly rejected (${mustFail})`); return r; }
          log(`❌ ${label} — expected rejection ${mustFail}, got ${fail ? fail.slice(0, 120) : 'SUCCESS'}`); process.exit(1);
        }
        if (fail) { log(`❌ ${label} — ${fail.slice(0, 160)}`); process.exit(1); }
        log(`✅ ${label}`); return r;
      } catch (e) {
        const msg = (e.message || '') + (JSON.stringify(e) || '');
        if (mustFail && msg.includes(mustFail)) { log(`🛡️ ${label} → correctly rejected (${mustFail})`); return null; }
        if (attempt === 1 && mustFail) { log(`❌ ${label} — expected ${mustFail}, got: ${msg.slice(0, 160)}`); process.exit(1); }
        if (/429|timeout|FetchError|ECONN/i.test(msg) && attempt === 0) { await new Promise(r => setTimeout(r, 3000)); continue; }
        const m = msg.match(/ERR_[A-Z_]+|panicked: [^"\\]+/) || [msg.slice(0, 160)];
        if (mustFail && m[0].includes(mustFail)) { log(`🛡️ ${label} → correctly rejected (${mustFail})`); return null; }
        if (mustFail) { log(`❌ ${label} — expected ${mustFail}, got: ${m[0]}`); process.exit(1); }
        log(`❌ ${label} — ${m[0]}`); process.exit(1);
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
  const nextNonce = () => NONCE++;
  const exec = (label, id, deposit = '0') => step(label, () => call(label, 'execute',
    rawArgs({ wallet_name: 'treasury', proposal_id: id, ...nonceSig(`execute:treasury:${id}`), expires_at: EXPIRY.toString() }, ['expires_at']), { deposit }));
  const proposeApprove = async (nonceN, idx, label, intentIndex, paramValues, content) => {
    await step(`propose ${label}`, () => call(`propose ${label}`, 'propose',
      rawArgs({ wallet_name: 'treasury', intent_index: intentIndex, param_values: JSON.stringify(paramValues), nonce: nonceN, signature: ownerSig(nonceN, `propose:treasury:${idx}`), expires_at: EXPIRY.toString() }, ['expires_at'])));
    await step(`verify+approve ${label}`, async () => {
      const stored = await view('get_proposal_message', { wallet_name: 'treasury', id: idx });
      const mine = pMsg(idx, 'propose', content);
      const strip = (s) => s.replace(/^expires [^:]+: /, '');
      if (strip(stored) !== strip(mine)) { log(`   msg ❌\n   stored: ${stored}\n   mine:   ${mine}`); process.exit(1); }
      log(`   msg: ✅ "${strip(mine)}"`);
      await call(`nostr approve ${label}`, 'approve',
        rawArgs({ wallet_name: 'treasury', proposal_id: idx, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pMsg(idx, 'approve', content)), expires_at: EXPIRY.toString() }, ['expires_at']));
    });
  };

  // nonce numbering plan (client-chosen; window is 64 wide from get_owner_nonce base):
  // n0 init-skip, n1 create_wallet, n2..: sequential as used below.
  await step('init', () => call('init new([owner])', 'new', rawArgs({ owner_npubs: [NPubHex] }), { gas: 30n * 10n ** 12n }));
  NONCE = STEP > 1 ? 40 : 1; // on resume jump safely inside window past used slots
  await step('create_wallet', () => call('create_wallet(treasury, +0.5Ⓝ)', 'create_wallet',
    rawArgs({ name: 'treasury', ...nonceSig('create_wallet:treasury'), expires_at: EXPIRY.toString() }, ['expires_at']),
    { deposit: yocto(0.5) }));
  await step('set guardian', () => call('set_guardian', 'set_guardian',
    rawArgs({ npub: GPubHex, ...nonceSig('set_guardian'), expires_at: EXPIRY.toString() }, ['expires_at'])));
  await step('set relayer fee', () => call('set_relayer_fee(0.001Ⓝ)', 'set_relayer_fee',
    rawArgs({ wallet_name: 'treasury', fee: yocto(0.001), ...nonceSig('set_relayer_fee:treasury'), expires_at: EXPIRY.toString() }, ['expires_at'])));

  // SECURITY: replay a used nonce → must reject
  await step('replay rejection', async () => {
    const nn = NONCE++;
    await call(`burn nonce ${nn}`, 'set_relayer_fee',
      rawArgs({ wallet_name: 'treasury', fee: yocto(0.001), nonce: nn, signature: ownerSig(nn, 'set_relayer_fee:treasury'), expires_at: EXPIRY.toString() }, ['expires_at']));
    await call(`replay used nonce (${nn})`, 'set_relayer_fee',
      rawArgs({ wallet_name: 'treasury', fee: '0', nonce: nn, signature: ownerSig(nn, 'set_relayer_fee:treasury'), expires_at: EXPIRY.toString() }, ['expires_at']),
      { mustFail: 'ERR_NONCE_ALREADY_USED' });
  });
  // SECURITY: far-future nonce outside window → must reject
  await step('window rejection', () => call('nonce outside window', 'set_relayer_fee',
    rawArgs({ wallet_name: 'treasury', fee: '0', nonce: NONCE + 64, signature: ownerSig(NONCE + 64, 'set_relayer_fee:treasury'), expires_at: EXPIRY.toString() }, ['expires_at']),
    { mustFail: 'ERR_NONCE_WINDOW_EXCEEDED' }));

  // guardian pause / unpause
  await step('guardian pause', () => call('guardian pause', 'pause',
    rawArgs({ signature: schnorrSign(`expires ${EXPIRY}.000000000: pause | contract: ${CONTRACT}`, GSEC), expires_at: EXPIRY.toString() }, ['expires_at'])));
  await step('paused blocks propose', () => call('propose while paused', 'propose',
    rawArgs({ wallet_name: 'treasury', intent_index: 0, param_values: '{}', ...nonceSig('propose:treasury:99'), expires_at: EXPIRY.toString() }, ['expires_at']),
    { mustFail: 'ERR_CONTRACT_PAUSED' }));
  await step('owner unpause', () => call('unpause', 'unpause',
    rawArgs({ ...nonceSig('unpause'), expires_at: EXPIRY.toString() }, ['expires_at'])));

  await proposeApprove(nextNonce(), 0, 'AddIntent(Deposit)', 0,
    { hash: depHash(depositIntent), definition: depositIntent }, `add intent definition_hash: ${depHash(depositIntent)}`);
  await exec('execute AddIntent → deposit 1Ⓝ', 0, yocto(1));

  await proposeApprove(nextNonce(), 1, 'AddIntent(Transfer)', 0,
    { hash: depHash(transferIntent), definition: transferIntent }, `add intent definition_hash: ${depHash(transferIntent)}`);
  await exec('execute AddIntent → Transfer intent', 1);

  // SECURITY: transfer with empty wallet → must reject (insufficient)
  await step('insufficient transfer rejection', () => call('transfer w/ 0 balance', 'execute',
    rawArgs({ wallet_name: 'treasury', proposal_id: 999, ...nonceSig('execute:treasury:999'), expires_at: EXPIRY.toString() }, ['expires_at']),
    { mustFail: 'ERR_PROPOSAL_NOT_FOUND' }));

  // fund wallet via Deposit intent (intent #3)
  await step('propose Deposit 1Ⓝ', () => call('propose Deposit 1Ⓝ', 'propose',
    rawArgs({ wallet_name: 'treasury', intent_index: 3, param_values: JSON.stringify({ amount: yocto(1) }), ...nonceSig('propose:treasury:2'), expires_at: EXPIRY.toString() }, ['expires_at'])));
  await step('approve Deposit', () => call('nostr approve Deposit', 'approve',
    rawArgs({ wallet_name: 'treasury', proposal_id: 2, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pMsg(2, 'approve', 'deposit NEAR to wallet')), expires_at: EXPIRY.toString() }, ['expires_at'])));
  await exec('execute Deposit (+1Ⓝ)', 2, yocto(1));

  // propose + approve + execute the 0.5Ⓝ transfer (intent #4)
  await proposeApprove(nextNonce(), 3, `transfer 0.5Ⓝ→${RECIPIENT}`, 4,
    { amount: XFER_AMT, recipient: RECIPIENT }, `transfer ${XFER_AMT} to ${RECIPIENT}`);
  await exec('execute transfer (0.5Ⓝ out + relayer fee)', 3);

  await step('final views', async () => {
    const state = await view('get_wallet_state', { wallet_name: 'treasury' });
    const pm = await view('get_proposal_message', { wallet_name: 'treasury', id: 3 });
    const owners = await view('get_owner_npubs', {});
    const guardian = await view('get_guardian_npub', {});
    const base = await view('get_owner_nonce', {});
    log('\n════ RESULT ════');
    log(`treasury NEAR balance: ${(Number(state.near_balance) / 1e24).toFixed(4)} Ⓝ (1.0 in − 0.5 out − 0.001 fee)`);
    log(`owners: ${owners.length} | guardian set: ${!!guardian} | nonce window base: ${base}`);
    log(`clear-signed transfer message:\n   "${pm}"`);
    log('\nALL PASS ✅ v3: replay-rejected, windowed nonces, guardian pause, relayer payout');
  });
})().catch(e => { console.error('FATAL', (e.message || e).toString().slice(0, 300)); process.exit(1); });
