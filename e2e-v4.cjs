/**
 * nostr-msig v4 E2E — session keys via NEP-611 gas keys on
 * nmsig.vault.kampy.testnet (testnet protocol 85).
 *
 * Flow:
 *  1. create wallet "sessionw" (+0.5Ⓝ storage)
 *  2. AddIntent(Deposit) + execute; AddIntent(Transfer) + execute
 *  3. execute Deposit → +1Ⓝ internal balance (relayer path)
 *  4. add_session_key: FRESH ed25519 key, 8 nonces, 0.3Ⓝ initial gas, 2h expiry
 *     + short-lived key (1.5s expiry, 0.05Ⓝ)
 *  5. verify view_access_key: GasKeyFunctionCall permission with balances
 *  6. session_ping via near-cli-rs 0.30 (auto TransactionV1 GasKeyNonce)
 *  7. submit_action quick Transfer 0.1Ⓝ via the gas key (owner still signs)
 *     → wallet balance −0.1Ⓝ, recipient +0.1Ⓝ, gas-key balance decreased
 *  8. auth rejections: wrong wallet, non-session signer, expired key
 *  9. refresh_session top-up (+0.1Ⓝ → balance increases)
 * 10. revoke both keys → view_access_key errors, list_sessions empty
 *
 * Owner nsec = sha256('nostr-msig-e2e-test-v1') — same as v3 e2e.
 * Gas-key txs signed by near-cli-rs ≥0.30 (near-api-js 0.44 cannot encode
 * TransactionV1 GasKeyNonce).
 */
const ROOT = '/Users/asil/.openclaw/workspace';
const { schnorr } = require(ROOT + '/outlayer-wallet/node_modules/@noble/curves/secp256k1');
const { sha256 } = require(ROOT + '/outlayer-wallet/node_modules/@noble/hashes/sha256');
const { bytesToHex } = require(ROOT + '/outlayer-wallet/node_modules/@noble/hashes/utils');
const nearAPI = require(ROOT + '/node_modules/near-api-js');
const { execFile } = require('child_process');
const fs = require('fs');

const CONTRACT = 'nmsig.vault.kampy.testnet';
const RPC = 'https://rpc.testnet.fastnear.com';
const NEAR_BIN = process.env.HOME + '/.cargo/bin/near';
const WALLET = process.env.RESUME_WALLET || ('sw' + (Date.now() % 100000).toString(36)); // unique per run
const STAGE = process.env.RESUME_STAGE || null; // e.g. 'deposit' to skip wallet+intents
const RECIPIENT = 'vault.kampy.testnet';
const XFER = '100000000000000000000000'; // 0.1 NEAR

const NSEC = sha256(new TextEncoder().encode('nostr-msig-e2e-test-v1'));
const NPubHex = bytesToHex(schnorr.getPublicKey(NSEC));

const yocto = (n) => (BigInt(Math.round(n * 1e6)) * 10n ** 18n).toString();
const nowNs = () => BigInt(Date.now()) * 1_000_000n;
const EXPIRY = (BigInt(Math.floor(Date.now() / 1000)) + 7200n) * 1_000_000_000n;
const schnorrSign = (m, sk = NSEC) => bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(m)), sk));
const ownerSig = (nonce, action) => schnorrSign(`expires ${EXPIRY}.000000000: ${action} | nonce: ${nonce} | contract: ${CONTRACT}`);
const depHash = (def) => bytesToHex(sha256(new TextEncoder().encode(def)));
// JSON with select u64/u128 fields as RAW digits (serde u64 rejects strings)
const rawArgs = (obj, big = []) => Buffer.from(JSON.stringify(
  JSON.parse('{' + Object.entries(obj).map(([k, v]) => big.includes(k) ? `"${k}":${v}` : `"${k}":${JSON.stringify(v)}`).join(',') + '}'),
  (k, v) => typeof v === 'bigint' ? v.toString() : v));

const mkIntent = (type, template, params, name) => JSON.stringify({
  wallet_name: WALLET, index: 0, intent_type: type, name,
  template, proposers: [], approvers: [], nostr_approvers: [NPubHex],
  approval_threshold: 1, cancellation_threshold: 1, timelock_seconds: 0,
  params, execution_gas_tgas: 50, active: true, active_proposal_count: 0,
});
const depositIntent = mkIntent('Deposit', 'deposit NEAR to wallet',
  [{ name: 'amount', param_type: 'U128', max_value: null }], 'Deposit NEAR');
const transferIntent = mkIntent('Transfer', 'transfer {amount} yoctoNEAR to {recipient}',
  [{ name: 'amount', param_type: 'U128', max_value: yocto(100) },
   { name: 'recipient', param_type: 'AccountId', max_value: null }], 'Transfer NEAR');

const TXS = [];
const sh = (cmd, args) => new Promise((res) => execFile(cmd, args, { maxBuffer: 12e6 }, (err, stdout, stderr) => res({ err, stdout, stderr })));

(async () => {
  const cred = JSON.parse(fs.readFileSync(`${process.env.HOME}/.near-credentials/testnet/${CONTRACT}.json`, 'utf8'));
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  await keyStore.setKey('testnet', CONTRACT, nearAPI.KeyPair.fromString(cred.private_key));
  const near = await nearAPI.connect({ networkId: 'testnet', nodeUrl: RPC, keyStore });
  const acct = await near.account(CONTRACT);
  const log = (...a) => console.log(...a);

  const call = async (label, method, args, { gas = 100n * 10n ** 12n, deposit = '0', mustFail = null, throwOnError = false } = {}) => {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const r = await acct.functionCall({ contractId: CONTRACT, methodName: method, args, gas: gas.toString(), attachedDeposit: deposit });
        if (r.transaction_outcome?.id) TXS.push(`${method}: ${r.transaction_outcome.id}`);
        const fail = r.status?.Failure ? JSON.stringify(r.status.Failure) : null;
        if (mustFail) {
          if (fail && fail.includes(mustFail)) { log(`🛡️  ${label} → correctly rejected (${mustFail})`); return r; }
          const e = new Error(`expected ${mustFail}, got ${fail ? fail.slice(0, 120) : 'SUCCESS'}`);
          if (throwOnError) throw e;
          log(`❌ ${label} — ${e.message}`); process.exit(1);
        }
        if (fail) {
          const m = fail.match(/ERR_[A-Z_]+|panicked: [^"\\]+/) || [fail.slice(0, 160)];
          const e = new Error(m[0]);
          if (throwOnError) throw e;
          log(`❌ ${label} — ${m[0]}`); process.exit(1);
        }
        log(`✅ ${label}`); return r;
      } catch (e) {
        const msg = (e.message || '') + (JSON.stringify(e) || '');
        if (mustFail && msg.includes(mustFail)) { log(`🛡️  ${label} → correctly rejected (${mustFail})`); return null; }
        if (attempt === 1) {
          if (throwOnError) throw e;
          if (mustFail) { log(`❌ ${label} — expected ${mustFail}, got: ${msg.slice(0, 160)}`); process.exit(1); }
          log(`❌ ${label} — ${msg.slice(0, 160)}`); process.exit(1);
        }
        if (/429|timeout|FetchError|ECONN|ERR_NONCE/i.test(msg) && attempt === 0) { await new Promise(r => setTimeout(r, 3000)); continue; }
        if (throwOnError) throw e;
        log(`❌ ${label} — ${msg.slice(0, 160)}`); process.exit(1);
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
  const rawQuery = async (params) => (await (await fetch(RPC, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: '1', method: 'query', params }) })).json());
  // retry a view until pred(out) is true (finality-lag safe)
  const viewUntil = async (label, method, args, pred, tries = 8) => {
    let last = null, lastErr = null;
    for (let i = 0; i < tries; i++) {
      try { const out = await view(method, args); last = out; if (pred(out)) return out; } catch (e) { lastErr = (e.message||'').slice(0,80); }
      await new Promise(r => setTimeout(r, 1500));
    }
    log(`❌ ${label} — condition not met after ${tries} tries; last=${JSON.stringify(last)} err=${lastErr}`); process.exit(1);
  };
  const viewAccessKey = async (pk) => (await rawQuery({ request_type: 'view_access_key', finality: 'final', account_id: CONTRACT, public_key: pk })).result?.permission;
  const acctBalance = async (id) => BigInt((await rawQuery({ request_type: 'view_account', finality: 'final', account_id: id })).result.amount);

  // Owner-nonce allocator: fresh base on demand, re-sign on nonce-window misses
  // (robust against a concurrent client also consuming owner nonces).
  const nextOwnerNonce = async () => {
    const base = await view('get_owner_nonce', {});
    const bm = await view('get_owner_nonce_bitmap', {});
    for (let off = 0; off < 64; off++) if (!(Number(bm) >> off & 1)) return Number(base) + off;
    throw new Error('nonce window full');
  };
  const sigFresh = async (action) => {
    const n = await nextOwnerNonce();
    return { nonce: n, signature: ownerSig(n, action) };
  };
  // owner-sig'd call: rebuilds args with a fresh nonce on ERR_NONCE_ failures
  const callO = async (label, method, buildArgs, opts = {}) => {
    for (let i = 0; i < 4; i++) {
      const s = await sigFresh(buildArgs.action);
      try { return await call(label, method, buildArgs.build(s), { ...opts, throwOnError: true }); }
      catch (e) { if (i === 3 || !/ERR_NONCE/.test(e.message || '')) throw e; await new Promise(r => setTimeout(r, 1500)); }
    }
  };

  // CLI call signed AS a gas key (near-cli-rs resolves TransactionV1 GasKeyNonce)
  const cliCall = async (label, method, argsJson, privateKey, { expectFail = null } = {}) => {
    const args = [
      'contract', 'call-function', 'as-transaction', CONTRACT, method, 'json-args', argsJson,
      'prepaid-gas', '50 Tgas', 'attached-deposit', '0 NEAR',
      'sign-as', CONTRACT, 'network-config', 'testnet',
      'sign-with-plaintext-private-key', privateKey, 'send',
    ];
    const { err, stdout, stderr } = await sh(NEAR_BIN, args);
    const all = stdout + stderr;
    const txHash = (all.match(/Transaction ID: ([A-Za-z0-9]+)/) || all.match(/"transaction_hash":\s*"([A-Za-z0-9]+)"/) || []).slice(1).find(Boolean);
    if (txHash) TXS.push(`${method} (gas-key): ${txHash}`);
    if (expectFail) {
      if (err || all.includes(expectFail)) { log(`🛡️  ${label} → correctly rejected (${expectFail})`); return { all }; }
      log(`❌ ${label} — expected ${expectFail}\n---\n${all.slice(0, 800)}\n---`); process.exit(1);
    }
    if (err && !/Success|transaction/i.test(all)) { log(`❌ ${label} — CLI error:\n${(stderr || '').slice(0, 600)}`); process.exit(1); }
    log(`✅ ${label}`); return { all };
  };
  // submit_action args as JSON text with raw u64 digits
  const submitArgs = (o) => '{' + [
    `"action":"${o.action}"`, `"wallet_name":"${o.wallet_name}"`, `"intent_index":${o.intent_index}`,
    `"proposal_id":${o.proposal_id}`, `"param_values":${JSON.stringify(o.param_values)}`,
    `"expires_at":${EXPIRY}`, `"nonce":${o.nonce}`, `"signature":"${o.signature}"`,
  ].join(',') + '}';

  log(`owner npub: ${NPubHex.slice(0, 20)}... | wallet: ${WALLET}`);
  log(`owner nonce base: ${await view('get_owner_nonce', {})} (fresh-nonce per call)`);

  // ── 1. create wallet ────────────────────────────────────────────────
  if (!STAGE) await callO(`create_wallet(${WALLET}, +0.5Ⓝ)`, 'create_wallet',
    { action: `create_wallet:${WALLET}`, build: s => rawArgs({ name: WALLET, ...s, expires_at: EXPIRY.toString() }, ['expires_at']) },
    { deposit: yocto(0.5) });

  // ── 2. AddIntent(Deposit) → intent #0 ──────────────────────────────
  const dh = depHash(depositIntent);
  if (!STAGE) await callO('propose AddIntent(Deposit)', 'propose',
    { action: `propose:${WALLET}:0`, build: s => rawArgs({ wallet_name: WALLET, intent_index: 0, param_values: JSON.stringify({ hash: dh, definition: depositIntent }), ...s, expires_at: EXPIRY.toString() }, ['expires_at']) });
  const pm0 = STAGE ? null : (await view('get_proposal_message', { wallet_name: WALLET, id: 0 })).replace(': propose ', ': approve ');
  if (!STAGE) await call('nostr approve AddIntent(Deposit)', 'approve',
    rawArgs({ wallet_name: WALLET, proposal_id: 0, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pm0), expires_at: EXPIRY.toString() }, ['expires_at']));
  if (!STAGE) await callO('execute AddIntent(Deposit)', 'execute',
    { action: `execute:${WALLET}:0`, build: s => rawArgs({ wallet_name: WALLET, proposal_id: 0, ...s, expires_at: EXPIRY.toString() }, ['expires_at']) });

  // ── 3. AddIntent(Transfer) → intent #1 ─────────────────────────────
  const th = depHash(transferIntent);
  if (!STAGE) await callO('propose AddIntent(Transfer)', 'propose',
    { action: `propose:${WALLET}:1`, build: s => rawArgs({ wallet_name: WALLET, intent_index: 0, param_values: JSON.stringify({ hash: th, definition: transferIntent }), ...s, expires_at: EXPIRY.toString() }, ['expires_at']) });
  const pm1 = STAGE ? null : (await view('get_proposal_message', { wallet_name: WALLET, id: 1 })).replace(': propose ', ': approve ');
  if (!STAGE) await call('nostr approve AddIntent(Transfer)', 'approve',
    rawArgs({ wallet_name: WALLET, proposal_id: 1, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pm1), expires_at: EXPIRY.toString() }, ['expires_at']));
  if (!STAGE) await callO('execute AddIntent(Transfer)', 'execute',
    { action: `execute:${WALLET}:1`, build: s => rawArgs({ wallet_name: WALLET, proposal_id: 1, ...s, expires_at: EXPIRY.toString() }, ['expires_at']) });

  // ── 4. Deposit 1Ⓝ (intent #0, relayer path) ────────────────────────
  let balNow = 0;
  for (let i = 0; i < 5 && balNow < 0.6e24; i++) { try { balNow = Number(await view('get_wallet_near_balance', { wallet_name: WALLET })); } catch (e) {} if (balNow < 0.6e24) await new Promise(r => setTimeout(r, 1500)); }
  while (balNow < 0.6e24) {
    const wst = await view('get_wallet_state', { wallet_name: WALLET });
    const pid = wst.wallet.proposal_index;
    await callO(`propose Deposit 1Ⓝ (proposal #${pid})`, 'propose',
      { action: `propose:${WALLET}:${pid}`, build: s => rawArgs({ wallet_name: WALLET, intent_index: 3, param_values: JSON.stringify({ amount: yocto(1) }), ...s, expires_at: EXPIRY.toString() }, ['expires_at']) });
    const pm2 = (await view('get_proposal_message', { wallet_name: WALLET, id: pid })).replace(': propose ', ': approve ');
    await call('nostr approve Deposit', 'approve',
      rawArgs({ wallet_name: WALLET, proposal_id: pid, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pm2), expires_at: EXPIRY.toString() }, ['expires_at']));
    await callO('execute Deposit (+1Ⓝ)', 'execute',
      { action: `execute:${WALLET}:${pid}`, build: s => rawArgs({ wallet_name: WALLET, proposal_id: pid, ...s, expires_at: EXPIRY.toString() }, ['expires_at']) },
      { deposit: yocto(1) });
    balNow = Number(await viewUntil('wallet funded after deposit', 'get_wallet_near_balance', { wallet_name: WALLET }, v => Number(v) >= 0.6e24));
  }
  const bal1 = await viewUntil('wallet funded ≥0.6 (resume-aware)', 'get_wallet_near_balance', { wallet_name: WALLET }, v => Number(v) >= 0.6e24);
  log(`   wallet balance: ${Number(bal1) / 1e24} Ⓝ`);

  // cleanup any stale sessions from a previous partial run
  const stale = await view('list_sessions', { wallet: WALLET });
  for (const m of stale) {
    await callO(`revoke stale session ${m.public_key.slice(0, 10)}…`, 'revoke_session',
      { action: `revoke_session:${m.public_key}`, build: s => rawArgs({ public_key: m.public_key, ...s, expires_at_sig: EXPIRY.toString() }, ['expires_at_sig']) });
  }

  // ── 5. add_session_key (main 2h + short 1.5s) ───────────────────────
  const kp = nearAPI.KeyPair.fromRandom('ed25519');
  const pkHex = Buffer.from(kp.publicKey.data).toString('hex');
  const pk58 = kp.publicKey.toString(); // base58 form for RPC view_access_key
  const secret = kp.secretKey;
  const kp2 = nearAPI.KeyPair.fromRandom('ed25519');
  const pk2Hex = Buffer.from(kp2.publicKey.data).toString('hex');
  const pk258 = kp2.publicKey.toString();

  const exp2h = Number(nowNs() + 7200n * 1_000_000_000n);
  const exp1s = Number(nowNs() + 30_000_000_000n);
  await callO(`add_session_key main (${pkHex.slice(0, 12)}… 0.3Ⓝ 8 lanes)`, 'add_session_key',
    { action: `add_session_key:${pkHex}`, build: s => rawArgs({ public_key: pkHex, num_nonces: 8, expires_at: exp2h, wallet: WALLET, label: 'e2e-main', initial_gas: yocto(0.3), ...s, expires_at_sig: EXPIRY.toString() }, ['expires_at', 'expires_at_sig']) });
  await callO(`add_session_key short (${pk2Hex.slice(0, 12)}… 30s)`, 'add_session_key',
    { action: `add_session_key:${pk2Hex}`, build: s => rawArgs({ public_key: pk2Hex, num_nonces: 1, expires_at: exp1s, wallet: WALLET, label: 'e2e-short', initial_gas: yocto(0.05), ...s, expires_at_sig: EXPIRY.toString() }, ['expires_at', 'expires_at_sig']) });

  // ── 6. verify gas keys on-chain ─────────────────────────────────────
  const viewAccessKeyUntil = async (pk, tries = 10) => {
    for (let i = 0; i < tries; i++) {
      const p = await viewAccessKey(pk);
      if (p?.GasKeyFunctionCall?.balance !== undefined) return p;
      await new Promise(r => setTimeout(r, 1500));
    }
    log(`❌ gas key ${pk} not visible after ${tries} tries`); process.exit(1);
  };
  const perm1 = await viewAccessKeyUntil(pk58);
  const balField = perm1?.GasKeyFunctionCall?.balance;
  if (balField === undefined) { log(`❌ main key is not a gas key: ${JSON.stringify(perm1).slice(0, 200)}`); process.exit(1); }
  log(`✅ main key = GasKeyFunctionCall { balance: ${Number(balField) / 1e24}Ⓝ, num_nonces: ${perm1.GasKeyFunctionCall.num_nonces}, methods: [${perm1.GasKeyFunctionCall.method_names}] }`);
  if (Number(balField) !== 0.3e24) { log(`❌ expected 0.3Ⓝ, got ${balField}`); process.exit(1); }
  const perm2 = await viewAccessKeyUntil(pk258);
  log(`✅ short key = GasKeyFunctionCall { balance: ${Number(perm2.GasKeyFunctionCall.balance) / 1e24}Ⓝ }`);

  // ── 7. session_ping as gas key via CLI (TransactionV1) ──────────────
  const ping = await cliCall('session_ping via gas key (TransactionV1)', 'session_ping', '{}', secret);
  const pong = (ping.all.match(/pong:[^"\\,}\s]+/g) || []).join(' ');
  if (!pong) { log(`❌ ping output missing pong:\n${ping.all.slice(0, 600)}`); process.exit(1); }
  log(`   → ${pong}`);

  // ── 8. submit_action quick Transfer 0.1Ⓝ via gas key ────────────────
  const quickParams = JSON.stringify({ amount: XFER, recipient: RECIPIENT });
  // converged reads: two consecutive identical values (finality-lag safe)
  const readConverged = async (fn, tries = 8) => {
    let prev;
    for (let i = 0; i < tries; i++) {
      const v = await fn();
      if (prev !== undefined && prev === v) return v;
      prev = v;
      await new Promise(r => setTimeout(r, 1800));
    }
    return prev;
  };
  const wBefore = await readConverged(() => view('get_wallet_near_balance', { wallet_name: WALLET })).then(BigInt);
  const rBefore = await readConverged(() => acctBalance(RECIPIENT));
  let kBefore = 300000000000000000000000n; // deterministic initial funding; refine if readable
  try { const k = await readConverged(async () => { const p = await viewAccessKey(pk58); return p.GasKeyFunctionCall ? BigInt(p.GasKeyFunctionCall.balance) : undefined; }); if (k !== undefined) kBefore = k; } catch (e) {}
  let submit;
  for (let i = 0; i < 4; i++) {
    const qn = await nextOwnerNonce();
    const quickSig = ownerSig(qn, `quick:${WALLET}:4:${quickParams.slice(0, 64)}`);
    submit = await cliCall('submit_action quick Transfer 0.1Ⓝ via gas key', 'submit_action',
      submitArgs({ action: 'quick', wallet_name: WALLET, intent_index: 4, proposal_id: 0, param_values: quickParams, nonce: qn, signature: quickSig }),
      secret);
    if (/SuccessValue|Succeeded/i.test(submit.all)) break;
    if (!/ERR_NONCE/.test(submit.all) || i === 3) { log(`❌ submit_action not successful:\n${submit.all.slice(0, 800)}`); process.exit(1); }
    await new Promise(r => setTimeout(r, 1500));
  }
  log(`   wBefore=${wBefore}`);
  const wAfter = BigInt(await viewUntil('wallet −0.1Ⓝ', 'get_wallet_near_balance', { wallet_name: WALLET }, v => BigInt(v) <= wBefore - 100000000000000000000n && BigInt(v) >= wBefore - 450000000000000000000000n));
  let rAfter = rBefore;
  for (let i = 0; i < 8 && rAfter === rBefore; i++) { rAfter = await acctBalance(RECIPIENT); if (rAfter === rBefore) await new Promise(r => setTimeout(r, 1500)); }
  let kAfter = kBefore;
  for (let i = 0; i < 10 && kAfter >= kBefore; i++) { try { kAfter = BigInt((await viewAccessKey(pk58)).GasKeyFunctionCall.balance); } catch (e) {} if (kAfter >= kBefore) await new Promise(r => setTimeout(r, 1500)); }
  log(`   wallet:  ${Number(wBefore) / 1e24} → ${Number(wAfter) / 1e24} Ⓝ`);
  log(`   recip:   ${Number(rBefore) / 1e24} → ${Number(rAfter) / 1e24} Ⓝ (Δ +${(Number(rAfter - rBefore) / 1e24).toFixed(6)})`);
  log(`   gas-key: ${Number(kBefore) / 1e24} → ${Number(kAfter) / 1e24} Ⓝ (spent ${(Number(kBefore - kAfter) / 1e24).toFixed(6)})`);
  if (wBefore - wAfter < 100000000000000000000n || wBefore - wAfter > 450000000000000000000000n) { log(`❌ wallet balance delta out of range: ${(Number(wBefore - wAfter)/1e24)}`); process.exit(1); }
  if (rAfter - rBefore < 100000000000000000000n) { log(`❌ recipient delta < 0.1Ⓝ: ${(Number(rAfter - rBefore)/1e24)}`); process.exit(1); }
  if (kAfter >= kBefore) { log('❌ gas key balance did not decrease'); process.exit(1); }

  // ── 9. auth rejections ──────────────────────────────────────────────
  for (let i = 0; i < 4; i++) {
    const wn = await nextOwnerNonce();
    const r = await cliCall('submit_action wrong wallet → rejected', 'submit_action',
      submitArgs({ action: 'quick', wallet_name: 'treasury', intent_index: 4, proposal_id: 0, param_values: quickParams, nonce: wn, signature: ownerSig(wn, `quick:treasury:4:${quickParams.slice(0, 64)}`) }),
      secret, { expectFail: 'ERR_SESSION_WALLET_MISMATCH' });
    if (r && /ERR_SESSION_WALLET_MISMATCH|rejected/.test(r.all || '') ) break;
    if (i === 3) process.exit(1);
    await new Promise(r2 => setTimeout(r2, 1500));
  }
  const nn = await nextOwnerNonce();
  await call('submit_action non-session signer → rejected', 'submit_action',
    rawArgs({ action: 'quick', wallet_name: WALLET, intent_index: 4, proposal_id: 0, param_values: quickParams, expires_at: EXPIRY.toString(), nonce: nn, signature: ownerSig(nn, `quick:${WALLET}:4:${quickParams.slice(0, 64)}`) }, ['expires_at']),
    { mustFail: 'ERR_NOT_SESSION_KEY' });
  log('   waiting 32s for short session to expire…');
  await new Promise(r => setTimeout(r, 32000));
  await cliCall('session_ping expired key → rejected', 'session_ping', '{}', kp2.secretKey, { expectFail: 'ERR_SESSION_EXPIRED' });

  // ── 10. refresh_session top-up (+0.1Ⓝ) ─────────────────────────────
  await callO('refresh_session main (+0.1Ⓝ)', 'refresh_session',
    { action: `refresh_session:${pkHex}:${yocto(0.1)}`, build: s => rawArgs({ public_key: pkHex, amount: yocto(0.1), ...s, expires_at_sig: EXPIRY.toString() }, ['expires_at_sig']) });
  let kAfter2 = kAfter;
  for (let i = 0; i < 8 && kAfter2 <= kAfter; i++) { kAfter2 = BigInt((await viewAccessKey(pk58)).GasKeyFunctionCall.balance); if (kAfter2 <= kAfter) await new Promise(r => setTimeout(r, 1500)); }
  log(`   gas-key balance after refresh: ${Number(kAfter2) / 1e24} Ⓝ`);
  if (kAfter2 <= kAfter) { log('❌ refresh did not increase balance'); process.exit(1); }

  // ── 11. revoke both; keys vanish ────────────────────────────────────
  await callO('revoke_session short', 'revoke_session',
    { action: `revoke_session:${pk2Hex}`, build: s => rawArgs({ public_key: pk2Hex, ...s, expires_at_sig: EXPIRY.toString() }, ['expires_at_sig']) });
  await callO('revoke_session main', 'revoke_session',
    { action: `revoke_session:${pkHex}`, build: s => rawArgs({ public_key: pkHex, ...s, expires_at_sig: EXPIRY.toString() }, ['expires_at_sig']) });
  const keyGone = async (pk) => {
    for (let i = 0; i < 10; i++) {
      const r = await rawQuery({ request_type: 'view_access_key', finality: 'final', account_id: CONTRACT, public_key: pk });
      if (r.error || r.result?.permission === undefined) return true;
      await new Promise(rr => setTimeout(rr, 1500));
    }
    return false;
  };
  if (!(await keyGone(pk58))) { log(`❌ main key still exists`); process.exit(1); }
  if (!(await keyGone(pk258))) { log(`❌ short key still exists`); process.exit(1); }
  await viewUntil('list_sessions empty', 'list_sessions', { wallet: WALLET }, v => Array.isArray(v) && v.length === 0);

  log('\n════ RESULT ════');
  log('ALL PASS ✅ v4 session keys: gas-key ping, relayer-free quick transfer, balance asserts, expiry/wallet/signer rejections, refresh, revoke');
  log('tx hashes:\n' + TXS.map(t => '  ' + t).join('\n'));
})().catch(e => { console.error('FATAL', (e.message || e).toString().slice(0, 400)); process.exit(1); });
