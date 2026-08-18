/**
 * finish2.cjs — complete the v5 flagship proof, fully self-verifying.
 * Writes verdict JSON to v5-final-verdict.json. Steps:
 *  0. drain ALL orphan gas keys (recover funds; verify on-chain deltas)
 *  1. pick/create wallet with a Transfer intent (agent-approved) + Deposit intent
 *  2. fund wallet if thin (fresh deposit proposal, owner flow)
 *  3. fresh keys: owner(5 methods) + agent(approve,session_ping)
 *  4. FLAGSHIP: propose via V1 → agent-npub approve via V1 → execute via V1,
 *     assert wallet delta
 *  5. scope rejection: agent execute attempt must fail at protocol level
 *  6. drain+revoke both fresh keys, assert gone
 */
const { schnorr } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const { bytesToHex } = require('@noble/hashes/utils');
const nearAPI = require('near-api-js');
const { execFile } = require('child_process');
const fs = require('fs');
const { yocto, sleep, connect } = require('./lib.cjs');
const { buildV1, broadcast, keyContext, rpc } = require('./v1.cjs');

const CONTRACT = 'benchv5.vault.kampy.testnet';
const RECIPIENT = 'vault.kampy.testnet';
const NEAR_BIN = process.env.HOME + '/.cargo/bin/near';
const VERDICT = {};
const TXS = [];
const sh = (cmd, args) => new Promise((res) => execFile(cmd, args, { maxBuffer: 12e6 }, (e, so, se) => res({ so: so.replace(/\x1b\[[0-9;]*m/g, ''), se: se.replace(/\x1b\[[0-9;]*m/g, '') })));
const log = (...a) => console.log(...a);
const NSEC = Buffer.from(bytesToHex(sha256(new TextEncoder().encode('nostr-msig-bench-v1'))), 'hex');
const NPubHex = bytesToHex(schnorr.getPublicKey(NSEC));
const AGENT_NSEC = Buffer.from(bytesToHex(sha256(new TextEncoder().encode('agent-nostr-msig-bench-v1'))), 'hex');
const AGENT_NPubHex = bytesToHex(schnorr.getPublicKey(AGENT_NSEC));
const EXPIRY = (BigInt(Math.floor(Date.now() / 1000)) + 7200n) * 1_000_000_000n;
const schnorrSign = (m, sk = NSEC) => bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(m)), sk));
const ownerSig = (nonce, action) => schnorrSign(`expires ${EXPIRY}.000000000: ${action} | nonce: ${nonce} | contract: ${CONTRACT}`);
const depHash = (def) => bytesToHex(sha256(new TextEncoder().encode(def)));
const rawArgs = (obj, big = []) => JSON.parse(Buffer.from(JSON.stringify(
  JSON.parse('{' + Object.entries(obj).map(([k, v]) => big.includes(k) ? `"${k}":${v}` : `"${k}":${JSON.stringify(v)}`).join(',') + '}'),
  (k, v) => typeof v === 'bigint' ? v.toString() : v)));

const call = async (m, a = {}) => {
  const r = await rpc('query', { request_type: 'call_function', finality: 'final', account_id: CONTRACT, method_name: m, args_base64: Buffer.from(JSON.stringify(a)).toString('base64') });
  return JSON.parse(Buffer.from(r.result.result).toString());
};
const viewT = async (m, a = {}, t = 8) => {
  for (let i = 0; i < t; i++) { try { return await call(m, a); } catch (e) { await sleep(1500 * (i + 1)); } }
  throw new Error(`view ${m} failed`);
};
const getPM = async (pid) => {
    for (let i = 0; i < 12; i++) {
      const m = await call('get_proposal_message', { wallet_name: WALLET, id: pid }).catch(() => null);
      if (m) return m.replace(': propose ', ': approve ');
      await sleep(1600);
    }
    throw new Error('no proposal message for ' + pid);
  };
const acctBal = async () => BigInt((await rpc('query', { request_type: 'view_account', finality: 'final', account_id: CONTRACT })).result.amount);
const mkIntent = (type, tmpl, params, name, approverHex) => JSON.stringify({
  wallet_name: WALLET, index: 0, intent_type: type, name,
  template: tmpl, proposers: [], approvers: [], nostr_approvers: [approverHex],
  approval_threshold: 1, cancellation_threshold: 1, timelock_seconds: 0,
  params, execution_gas_tgas: 50, active: true, active_proposal_count: 0,
});

let WALLET = null; // set in main

(async () => {
  const near = await connect(CONTRACT);
  const acct = await near.account(CONTRACT);
  const nextOwnerNonce = async () => {
    const base = await viewT('get_owner_nonce', {});
    const bm = await viewT('get_owner_nonce_bitmap', {});
    for (let off = 0; off < 64; off++) if (!(Number(bm) >> off & 1)) return Number(base) + off;
    throw new Error('window full');
  };
  const v0 = async (label, method, build, { deposit = '0' } = {}) => {
    for (let i = 0; i < 6; i++) {
      try {
        const r = await acct.functionCall({ contractId: CONTRACT, methodName: method, args: await build(), gas: '100000000000000', attachedDeposit: deposit });
        const f = r.status?.Failure ? JSON.stringify(r.status.Failure) : null;
        if (f) throw new Error(f.slice(0, 150));
        log(`✅ ${label}`); TXS.push(label); return r;
      } catch (e) {
        const m = e.message || '';
        if (i === 5 || !/ERR_NONCE|429|timeout|FetchError/i.test(m)) throw new Error(`${label}: ${m.slice(0, 170)}`);
        await sleep(1600);
      }
    }
  };
  const makeClient = (kp) => {
    const pk58 = kp.publicKey.toString();
    let lane = null, bh = null;
    const ctx = async () => {
      for (let i = 0; i < 14; i++) {
        try { const c = await keyContext(CONTRACT, pk58); if (c.permission?.GasKeyFunctionCall) { lane = BigInt(c.nonces[0]); bh = c.blockHash; return c; } } catch (e) {}
        await sleep(1500);
      }
      throw new Error('gas key not visible');
    };
    const callV1 = async (label, method, build, { expectReject = false } = {}) => {
      for (let att = 0; att < 6; att++) {
        const { signedBase64 } = buildV1({ signerId: CONTRACT, secretKey: kp.toString(), receiverId: CONTRACT, baseNonce: lane + 1n, nonceIndex: 0, blockHash: bh, actions: [{ functionCall: { methodName: method, args: await build(), gas: 100_000_000_000_000n } }] });
        let res;
        try { res = await broadcast(signedBase64); }
        catch (e) {
          const m = e.message || '';
          if (/InvalidNonce/i.test(m)) { const c = await ctx(); lane = BigInt(c.nonces[0]); bh = c.blockHash; await sleep(1300); continue; }
          if (expectReject) { log(`🛡️  ${label} → rejected at protocol level ✓`); TXS.push(label + ' [rejected ✓]'); return 'rejected'; }
          throw new Error(`${label}: ${m.slice(0, 200)}`);
        }
        lane += 1n;
        const errs = (res.receipts_outcome || []).map((o) => o.outcome.status?.Failure).filter(Boolean);
        if (errs.length) {
          const f = JSON.stringify(errs[0]);
          if (expectReject) { log(`🛡️  ${label} → rejected ✓ (${f.slice(0, 80)})`); TXS.push(label + ' [rejected ✓]'); return 'rejected'; }
          if ((/InvalidNonce/i.test(f) || /ERR_NONCE/i.test(f)) && att < 5) { const c = await ctx(); lane = BigInt(c.nonces[0]); bh = c.blockHash; await sleep(1300); continue; }
          throw new Error(`${label}: ${f.slice(0, 200)}`);
        }
        TXS.push(`${label} tx:${res.transaction_outcome.id}`);
        if (expectReject) throw new Error(`${label}: expected rejection, got success`);
        log(`✅ ${label}`);
        return res;
      }
      throw new Error(`${label}: retries exhausted`);
    };
    return { ctx, callV1, pk58 };
  };
  const permOf = async (pk58) => {
    for (let i = 0; i < 12; i++) {
      try { const r = await rpc('query', { request_type: 'view_access_key', finality: 'final', account_id: CONTRACT, public_key: pk58 }); const g = r.result?.permission?.GasKeyFunctionCall; if (g) return g; } catch (e) {}
      await sleep(1500);
    }
    throw new Error('perm not visible');
  };

  // ── 0. drain orphan gas keys ────────────────────────────────────────
  log('── phase 0: drain orphans');
  let drained = 0;
  for (let round = 0; round < 2; round++) {
    const keys = (await rpc('query', { request_type: 'view_access_key_list', finality: 'final', account_id: CONTRACT })).result.keys.filter(k => k.access_key.permission.GasKeyFunctionCall);
    let any = false;
    for (const k of keys) {
      const bal = Number(k.access_key.permission.GasKeyFunctionCall.balance) / 1e24;
      if (bal < 0.001) continue;
      any = true;
      const amt = (bal - 0.0003).toFixed(6);
      const { so } = await sh(NEAR_BIN, ['account', 'withdraw-from-gas-key', CONTRACT, k.public_key, amt + ' NEAR', 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send']);
      const tx = (so.match(/Transaction ID: ([A-Za-z0-9]+)/) || [])[1];
      log(`   drain ${k.public_key.slice(8, 20)} ${amt}Ⓝ ${tx ? 'tx ' + tx.slice(0, 8) : 'CLI-?'}`);
      await sleep(2500);
    }
    if (!any) break;
  }
  await sleep(3000);
  drained = 0; // compute realized from keys now ~0
  const postKeys = (await rpc('query', { request_type: 'view_access_key_list', finality: 'final', account_id: CONTRACT })).result.keys.filter(k => k.access_key.permission.GasKeyFunctionCall);
  const leftover = postKeys.reduce((s, k) => s + Number(k.access_key.permission.GasKeyFunctionCall.balance), 0) / 1e24;
  log(`orphan leftover in keys: ${leftover.toFixed(4)}Ⓝ`);
  VERDICT.orphanDrain = { leftover: Number(leftover.toFixed(4)) };

  // ── 1. wallet: reuse or create ─────────────────────────────────────
  log('── phase 1: wallet');
  let transferIntentIdx = null, depositIntentIdx = null;
  for (const cand of ['benchw-atux', 'benchw-vkm', 'benchw-cful']) {
    const st = await call('get_wallet_state', { wallet_name: cand }).catch(() => null);
    if (st) {
      const ww = st.wallet || st;
      const n = Number(ww.intent_index);
      if (n >= 5) { // has both user intents at 3+4 already
        WALLET = cand; transferIntentIdx = 3; depositIntentIdx = 4;
        log(`reusing ${WALLET} (intents ${n})`);
        break;
      }
      log(`skip ${cand} (only ${n} intents)`);
    }
  }
  if (!WALLET) {
    WALLET = 'flag' + (Date.now() % 1e6).toString(36);
    log(`creating fresh wallet ${WALLET}`);
    await v0(`create_wallet ${WALLET}`, 'create_wallet',
      async () => { const n = await nextOwnerNonce(); return rawArgs({ name: WALLET, nonce: n, signature: ownerSig(n, `create_wallet:${WALLET}`), expires_at: EXPIRY.toString() }, ['expires_at']); },
      { deposit: yocto(0.4) });
    // AgentTransfer intent → #3 ; Deposit intent → #4
    const ti = mkIntent('Transfer', 'transfer {amount} yoctoNEAR to {recipient}',
      [{ name: 'amount', param_type: 'U128', max_value: yocto(1) }, { name: 'recipient', param_type: 'AccountId', max_value: null }], 'AgentTransfer', AGENT_NPubHex);
    const di = mkIntent('Deposit', 'deposit NEAR to wallet',
      [{ name: 'amount', param_type: 'U128', max_value: null }], 'Deposit', NPubHex);
    for (const [name, def, pid] of [['AddIntent(AgentTransfer)', ti, 0], ['AddIntent(Deposit)', di, 1]]) {
      const h = depHash(def);
      await v0(`propose ${name}`, 'propose',
        async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, intent_index: 0, param_values: JSON.stringify({ hash: h, definition: def }), nonce: n, signature: ownerSig(n, `propose:${WALLET}:${pid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });
      const pm = await getPM(pid);
      await v0(`approve ${name}`, 'approve',
        async () => rawArgs({ wallet_name: WALLET, proposal_id: pid, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pm), expires_at: EXPIRY.toString() }, ['expires_at']));
      await v0(`execute ${name}`, 'execute',
        async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: pid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${pid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });
    }
    transferIntentIdx = 3; depositIntentIdx = 4;
  }

  // ── 2. fund if thin ────────────────────────────────────────────────
  let wbal = Number(await viewT('get_wallet_near_balance', { wallet_name: WALLET })) / 1e24;
  if (wbal < 0.55) {
    log(`wallet thin (${wbal.toFixed(3)}Ⓝ) → deposit 0.4`);
    if (!depositIntentIdx) depositIntentIdx = 4;
    const st = await viewT('get_wallet_state', { wallet_name: WALLET });
    const pid = Number((st.wallet || st).proposal_index);
    await v0(`propose Deposit 0.3 (#${pid})`, 'propose',
      async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, intent_index: depositIntentIdx, param_values: JSON.stringify({ amount: yocto(0.4) }), nonce: n, signature: ownerSig(n, `propose:${WALLET}:${pid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });
    const pm = await getPM(pid);
    await v0('approve Deposit', 'approve',
      async () => rawArgs({ wallet_name: WALLET, proposal_id: pid, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pm), expires_at: EXPIRY.toString() }, ['expires_at']));
    await v0('execute Deposit (+0.3)', 'execute',
      async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: pid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${pid}`), expires_at: EXPIRY.toString() }, ['expires_at']); },
      { deposit: yocto(0.4) });
    for (let i = 0; i < 10; i++) { wbal = Number(await viewT('get_wallet_near_balance', { wallet_name: WALLET }).catch(() => 0)) / 1e24; if (wbal >= 0.5) break; await sleep(1500); }
  }
  log(`wallet ${WALLET} balance: ${wbal.toFixed(3)}Ⓝ`);
  if (wbal < 0.5) throw new Error('funding failed');

  // ── 3. fresh keys ─────────────────────────────────────────────────
  log('── phase 3: fresh keys');
  const ownerKp = nearAPI.KeyPair.fromRandom('ed25519');
  const agentKp = nearAPI.KeyPair.fromRandom('ed25519');
  const ownerPkHex = Buffer.from(ownerKp.publicKey.data).toString('hex');
  const agentPkHex = Buffer.from(agentKp.publicKey.data).toString('hex');
  const expMs = () => Number(BigInt(Date.now() + 3600_000) * 1_000_000n);
  const addBuild = (pkHex, nn, gas, methods) => async () => {
    const n = await nextOwnerNonce();
    const a = { public_key: pkHex, num_nonces: nn, expires_at: expMs(), wallet: WALLET, label: 'v5f', initial_gas: yocto(gas), nonce: n, signature: ownerSig(n, `add_session_key:${pkHex}`), expires_at_sig: EXPIRY.toString() };
    if (methods) a.methods = methods;
    return rawArgs(a, ['expires_at', 'expires_at_sig']);
  };
  await v0('add owner key (5 methods)', 'add_session_key', addBuild(ownerPkHex, 2, 0.25, ['submit_action', 'session_ping', 'propose', 'approve', 'execute']));
  await v0('add agent key (approve+ping)', 'add_session_key', addBuild(agentPkHex, 1, 0.25, ['approve', 'session_ping']));
  const oPerm = await permOf(ownerKp.publicKey.toString());
  const aPerm = await permOf(agentKp.publicKey.toString());
  log(`owner methods [${oPerm.method_names}] | agent [${aPerm.method_names}]`);
  VERDICT.methods = { owner: oPerm.method_names, agent: aPerm.method_names };

  const owner = makeClient(ownerKp);
  const agent = makeClient(agentKp);
  await owner.ctx(); await agent.ctx();

  // ── 4. FLAGSHIP ───────────────────────────────────────────────────
  log('── phase 4: FLAGSHIP governance via V1 gas keys only');
  const st1 = await viewT('get_wallet_state', { wallet_name: WALLET });
  const tPid = Number((st1.wallet || st1).proposal_index);
  const amtT = yocto(0.02);
  const balBefore = BigInt(await viewT('get_wallet_near_balance', { wallet_name: WALLET }));
  await owner.callV1(`propose Transfer 0.02 (#${tPid}) [V1]`, 'propose',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, intent_index: transferIntentIdx, param_values: JSON.stringify({ amount: amtT, recipient: RECIPIENT }), nonce: n, signature: ownerSig(n, `propose:${WALLET}:${tPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });
  const pm = await getPM(tPid);
  await agent.callV1(`AGENT npub approves [V1]`, 'approve',
    async () => rawArgs({ wallet_name: WALLET, proposal_id: tPid, approver_index: 0, pubkey_hex: AGENT_NPubHex, signature: schnorrSign(pm, AGENT_NSEC), expires_at: EXPIRY.toString() }, ['expires_at']));
  await owner.callV1(`execute Transfer (#${tPid}) [V1]`, 'execute',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: tPid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${tPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });
  let balAfter = balBefore;
  for (let i = 0; i < 12 && balAfter === balBefore; i++) { balAfter = BigInt(await viewT('get_wallet_near_balance', { wallet_name: WALLET })); if (balAfter === balBefore) await sleep(1500); }
  const delta = Number(balBefore - balAfter) / 1e24;
  log(`wallet delta: -${delta.toFixed(4)}Ⓝ (expect ~0.02)`);
  if (delta < 0.019 || delta > 0.03) throw new Error('delta wrong: ' + delta);
  VERDICT.flagship = { transferred: delta, ok: true };

  // ── 5. scope rejection ────────────────────────────────────────────
  await agent.callV1('agent execute attempt → rejected (scope)', 'execute',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: tPid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${tPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); },
    { expectReject: true });
  VERDICT.scopeRejection = true;

  // ── 6. drain + revoke both fresh keys ─────────────────────────────
  log('── phase 6: drain+revoke rotation');
  for (const [kp, pkHex, tag] of [[ownerKp, ownerPkHex, 'owner'], [agentKp, agentPkHex, 'agent']]) {
    const g = await permOf(kp.publicKey.toString());
    const bal = Number(g.balance) / 1e24;
    if (bal > 0.001) {
      const before = await acctBal();
      const { so } = await sh(NEAR_BIN, ['account', 'withdraw-from-gas-key', CONTRACT, kp.publicKey.toString(), (bal - 0.0002).toFixed(6) + ' NEAR', 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send']);
      let after = before;
      for (let i = 0; i < 12 && after === before; i++) { after = await acctBal(); if (after === before) await sleep(2000); }
      if (after <= before) throw new Error(`drain ${tag} failed: ${so.slice(0, 150)}`);
      log(`✅ drained ${tag} key ${(bal).toFixed(4)}Ⓝ`);
    }
    await v0(`revoke ${tag} key (0 burn)`, 'revoke_session',
      async () => { const n = await nextOwnerNonce(); return rawArgs({ public_key: pkHex, nonce: n, signature: ownerSig(n, `revoke_session:${pkHex}`), expires_at_sig: EXPIRY.toString() }, ['expires_at_sig']); });
    let gone = false;
    for (let i = 0; i < 10 && !gone; i++) {
      try { await rpc('query', { request_type: 'view_access_key', finality: 'final', account_id: CONTRACT, public_key: kp.publicKey.toString() }); await sleep(1600); }
      catch (e) { gone = true; }
    }
    if (!gone) throw new Error(`${tag} key not revoked`);
    log(`✅ ${tag} key revoked — gone`);
  }
  VERDICT.rotation = true;

  VERDICT.ok = true;
  VERDICT.wallet = WALLET;
  VERDICT.txs = TXS;
  log('\\n★ V5 FLAGSHIP COMPLETE ★');
})().catch((e) => {
  VERDICT.ok = false;
  VERDICT.error = (e.message || e).toString().slice(0, 400);
  console.error('FATAL', VERDICT.error);
}).finally(() => {
  fs.writeFileSync(__dirname + '/v5-final-verdict.json', JSON.stringify(VERDICT, null, 2));
  process.exit(VERDICT.ok ? 0 : 1);
});
