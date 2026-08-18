/**
 * finish.cjs — resume the v5 bench on the surviving benchw-atux wallet:
 * intents #3 (agent-approved Transfer) + #4 (Deposit) exist, deposit
 * proposal #2 is approved but unexecuted. This finishes the remaining
 * v5 checks: deposit execute, widened keys, flagship gas-key governance,
 * scope rejection, drain-then-revoke.
 */
const { schnorr } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const { bytesToHex } = require('@noble/hashes/utils');
const nearAPI = require('near-api-js');
const { execFile } = require('child_process');
const { yocto, sleep, connect, viewContract, npubFromHex } = require('./lib.cjs');
const { buildV1, broadcast, keyContext, rpc } = require('./v1.cjs');

const CONTRACT = process.env.BENCH_CONTRACT || 'benchv5.vault.kampy.testnet';
const WALLET = process.env.BENCH_WALLET || 'benchw-atux';
const RECIPIENT = process.env.BENCH_RECIPIENT || 'vault.kampy.testnet';
const NEAR_BIN = process.env.NEAR_BIN || process.env.HOME + '/.cargo/bin/near';

const NSEC = Buffer.from(bytesToHex(sha256(new TextEncoder().encode('nostr-msig-bench-v1'))), 'hex');
const NPubHex = bytesToHex(schnorr.getPublicKey(NSEC));
const AGENT_NSEC = Buffer.from(bytesToHex(sha256(new TextEncoder().encode('agent-nostr-msig-bench-v1'))), 'hex');
const AGENT_NPubHex = bytesToHex(schnorr.getPublicKey(AGENT_NSEC));
const EXPIRY = (BigInt(Math.floor(Date.now() / 1000)) + 7200n) * 1_000_000_000n;
const schnorrSign = (m, sk = NSEC) => bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(m)), sk));
const ownerSig = (nonce, action) => schnorrSign(`expires ${EXPIRY}.000000000: ${action} | nonce: ${nonce} | contract: ${CONTRACT}`);
const rawArgs = (obj, big = []) => JSON.parse(Buffer.from(JSON.stringify(
  JSON.parse('{' + Object.entries(obj).map(([k, v]) => big.includes(k) ? `"${k}":${v}` : `"${k}":${JSON.stringify(v)}`).join(',') + '}'),
  (k, v) => typeof v === 'bigint' ? v.toString() : v)));
const TXS = []; const PASS = [];
const sh = (cmd, args) => new Promise((res) => execFile(cmd, args, { maxBuffer: 12e6 }, (e, so, se) => res({ so: so.replace(/\x1b\[[0-9;]*m/g, ''), se: se.replace(/\x1b\[[0-9;]*m/g, '') })));
const view = async (method, args = {}, tries = 6) => {
  for (let i = 0; i < tries; i++) {
    try { return await viewContract(CONTRACT, method, args); } catch (e) { if (i === tries - 1) throw e; await sleep(1500 * (i + 1)); }
  }
};

(async () => {
  const near = await connect(CONTRACT);
  const acct = await near.account(CONTRACT);
  const nextOwnerNonce = async () => {
    const base = await view('get_owner_nonce', {});
    const bm = await view('get_owner_nonce_bitmap', {});
    for (let off = 0; off < 64; off++) if (!(Number(bm) >> off & 1)) return Number(base) + off;
    throw new Error('window full');
  };
  const v0 = async (label, method, build, { deposit = '0', mustFail = null } = {}) => {
    for (let i = 0; i < 6; i++) {
      try {
        const r = await acct.functionCall({ contractId: CONTRACT, methodName: method, args: await build(), gas: '100000000000000', attachedDeposit: deposit });
        const f = r.status?.Failure ? JSON.stringify(r.status.Failure) : null;
        if (mustFail) { if (f && f.includes(mustFail)) { console.log(`🛡️  ${label} → rejected (${mustFail}) ✓`); PASS.push(label); return r; } throw new Error(`want ${mustFail}, got ${f || 'ok'}`); }
        if (f) throw new Error(f.slice(0, 150));
        console.log(`✅ ${label}`); PASS.push(label); return r;
      } catch (e) {
        const m = e.message || '';
        if (mustFail && m.includes(mustFail)) { console.log(`🛡️  ${label} → rejected (${mustFail}) ✓`); PASS.push(label); return null; }
        if (i === 5 || !/ERR_NONCE|429|timeout|FetchError/i.test(m)) throw new Error(`${label}: ${m.slice(0, 160)}`);
        await sleep(1500);
      }
    }
  };

  console.log(`v5 FINISHER — ${CONTRACT} / ${WALLET}`);
  // ── 1. execute the approved deposit proposal #2 (+0.55Ⓝ) ──────────
  const st0 = await view('get_wallet_state', { wallet_name: WALLET });
  const w = st0.wallet || st0;
  const depAmt = '0.55';
  // fresh deposit proposal on intent #4 (old #2 expired)
  const stD = await view('get_wallet_state', { wallet_name: WALLET });
  const depPid = (stD.wallet || stD).proposal_index;
  await v0(`propose Deposit ${depAmt}Ⓝ (#${depPid}, intent #4)`, 'propose',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, intent_index: 4, param_values: JSON.stringify({ amount: yocto(0.55) }), nonce: n, signature: ownerSig(n, `propose:${WALLET}:${depPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });
  {
    const pm0 = (await view('get_proposal_message', { wallet_name: WALLET, id: depPid })).replace(': propose ', ': approve ');
    await v0('nostr approve Deposit', 'approve',
      async () => rawArgs({ wallet_name: WALLET, proposal_id: depPid, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pm0), expires_at: EXPIRY.toString() }, ['expires_at']));
  }
  await v0(`execute Deposit (+${depAmt}Ⓝ)`, 'execute',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: depPid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${depPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); },
    { deposit: yocto(0.55) });
  let bal = 0;
  for (let i = 0; i < 10; i++) { const b = await view('get_wallet_near_balance', { wallet_name: WALLET }); bal = Number(b) / 1e24; if (bal > 0.4) break; await sleep(1500); }
  console.log(`   wallet balance: ${bal.toFixed(3)} Ⓝ`);
  if (bal < 0.4) { console.error('❌ deposit did not land'); process.exit(1); }

  // ── 2. keys: owner widened / agent scoped / default ────────────────
  const ownerKp = nearAPI.KeyPair.fromRandom('ed25519');
  const agentKp = nearAPI.KeyPair.fromRandom('ed25519');
  const defKp = nearAPI.KeyPair.fromRandom('ed25519');
  const METHODS = ['submit_action', 'session_ping', 'propose', 'approve', 'execute'];
  const expMs = () => Number(BigInt(Date.now() + 3600_000) * 1_000_000n);
  const addBuild = (pkHex, nn, gas, methods) => async () => {
    const n = await nextOwnerNonce();
    const a = { public_key: pkHex, num_nonces: nn, expires_at: expMs(), wallet: WALLET, label: 'v5', initial_gas: yocto(gas), nonce: n, signature: ownerSig(n, `add_session_key:${pkHex}`), expires_at_sig: EXPIRY.toString() };
    if (methods) a.methods = methods;
    return rawArgs(a, ['expires_at', 'expires_at_sig']);
  };
  const ownerPkHex = Buffer.from(ownerKp.publicKey.data).toString('hex');
  const agentPkHex = Buffer.from(agentKp.publicKey.data).toString('hex');
  const defPkHex = Buffer.from(defKp.publicKey.data).toString('hex');
  await v0('add owner key (5 methods, 0.15Ⓝ)', 'add_session_key', addBuild(ownerPkHex, 2, 0.15, METHODS));
  await v0('add agent key (approve+ping, 0.06Ⓝ)', 'add_session_key', addBuild(agentPkHex, 1, 0.06, ['approve', 'session_ping']));
  await v0('add default key (0.005Ⓝ)', 'add_session_key', addBuild(defPkHex, 1, 0.005, null));

  // permission checks
  const permOf = async (pk58) => {
    for (let i = 0; i < 10; i++) {
      try { const r = await rpc('query', { request_type: 'view_access_key', finality: 'final', account_id: CONTRACT, public_key: pk58 }); const g = r.result?.permission?.GasKeyFunctionCall; if (g) return g; } catch (e) {}
      await sleep(1500);
    }
    throw new Error('perm not visible: ' + pk58);
  };
  const oPerm = await permOf(ownerKp.publicKey.toString());
  if (JSON.stringify(oPerm.method_names) !== JSON.stringify(METHODS)) { console.error('❌ owner methods ' + oPerm.method_names); process.exit(1); }
  console.log(`✅ owner key methods = [${oPerm.method_names}]`);
  PASS.push('widened methods on-chain');
  const aPerm = await permOf(agentKp.publicKey.toString());
  if (JSON.stringify(aPerm.method_names) !== JSON.stringify(['approve', 'session_ping'])) { console.error('❌ agent methods'); process.exit(1); }
  const dPerm = await permOf(defKp.publicKey.toString());
  if (JSON.stringify(dPerm.method_names) !== JSON.stringify(['submit_action', 'session_ping'])) { console.error('❌ default methods'); process.exit(1); }
  console.log(`✅ agent scoped + default v4 scope confirmed`);
  PASS.push('agent scoped', 'v4 default compat');

  // ── 3. gas-key submission helpers (V1 pure JS) ────────────────────
  const makeClient = (kp) => {
    const pk58 = kp.publicKey.toString();
    let lane = null, blockHash = null;
    const ctx = async () => {
      for (let i = 0; i < 12; i++) {
        try { const c = await keyContext(CONTRACT, pk58); if (c.permission?.GasKeyFunctionCall) { lane = BigInt(c.nonces[0]); blockHash = c.blockHash; return c; } } catch (e) {}
        await sleep(1500);
      }
      throw new Error('key ctx');
    };
    const call = async (label, method, build, { mustFail = null } = {}) => {
      for (let attempt = 0; attempt < 6; attempt++) {
        const { signedBase64 } = buildV1({ signerId: CONTRACT, secretKey: kp.toString(), receiverId: CONTRACT, baseNonce: lane + 1n, nonceIndex: 0, blockHash, actions: [{ functionCall: { methodName: method, args: await build(), gas: 100_000_000_000_000n } }] });
        let res;
        try { res = await broadcast(signedBase64); }
        catch (e) {
          const m = e.message || '';
          if (/InvalidNonce/i.test(m)) { const c = await ctx(); lane = BigInt(c.nonces[0]); blockHash = c.blockHash; await sleep(1200); continue; }
          if (mustFail === 'PROTOCOL_SCOPE') { console.log(`🛡️  ${label} → rejected at protocol level ✓`); PASS.push(label); return; }
          throw new Error(`${label}: ${m.slice(0, 180)}`);
        }
        lane += 1n;
        const errs = (res.receipts_outcome || []).map((o) => o.outcome.status?.Failure).filter(Boolean);
        if (errs.length) {
          const f = JSON.stringify(errs[0]);
          if (mustFail && f.includes(mustFail)) { console.log(`🛡️  ${label} → rejected (${mustFail}) ✓`); PASS.push(label); return; }
          if ((/InvalidNonce/i.test(f) || /ERR_NONCE/i.test(f)) && attempt < 5) { const c = await ctx(); lane = BigInt(c.nonces[0]); blockHash = c.blockHash; await sleep(1200); continue; }
          throw new Error(`${label}: ${f.slice(0, 180)}`);
        }
        TXS.push(`${method} (V1): ${res.transaction_outcome.id}`);
        if (mustFail) throw new Error(`${label}: expected fail, got success`);
        console.log(`✅ ${label}`); PASS.push(label);
        return res;
      }
      throw new Error(`${label}: retries exhausted`);
    };
    return { ctx, call, pk58 };
  };
  const owner = makeClient(ownerKp);
  const agent = makeClient(agentKp);
  await owner.ctx(); await agent.ctx();

  // ── 4. FLAGSHIP: full governance via gas keys ─────────────────────
  const st1 = await view('get_wallet_state', { wallet_name: WALLET });
  const tPid = (st1.wallet || st1).proposal_index;
  const balBefore = BigInt(await view('get_wallet_near_balance', { wallet_name: WALLET }));
  await owner.call(`propose Transfer 0.03Ⓝ (#${tPid}) via V1 gas key`, 'propose',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, intent_index: 3, param_values: JSON.stringify({ amount: yocto(0.03), recipient: RECIPIENT }), nonce: n, signature: ownerSig(n, `propose:${WALLET}:${tPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });
  const pm = (await view('get_proposal_message', { wallet_name: WALLET, id: tPid })).replace(': propose ', ': approve ');
  await agent.call('AGENT npub approves via its own V1 gas key', 'approve',
    async () => rawArgs({ wallet_name: WALLET, proposal_id: tPid, approver_index: 0, pubkey_hex: AGENT_NPubHex, signature: schnorrSign(pm, AGENT_NSEC), expires_at: EXPIRY.toString() }, ['expires_at']));
  await owner.call(`execute Transfer (#${tPid}) via V1 gas key`, 'execute',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: tPid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${tPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });
  let balAfter = balBefore;
  for (let i = 0; i < 10 && balAfter === balBefore; i++) { balAfter = BigInt(await view('get_wallet_near_balance', { wallet_name: WALLET })); if (balAfter === balBefore) await sleep(1500); }
  const d = Number(balBefore - balAfter) / 1e24;
  if (d < 0.029 || d > 0.04) { console.error(`❌ delta ${d}`); process.exit(1); }
  console.log(`   wallet −${d.toFixed(3)}Ⓝ → ${RECIPIENT}`);
  PASS.push('flagship: governance via gas keys moved funds');

  // scope rejection
  await agent.call('agent execute attempt → out of scope', 'execute',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: tPid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${tPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); },
    { mustFail: 'PROTOCOL_SCOPE' });

  // ── 5. drain-then-revoke ───────────────────────────────────────────
  const kctx = await owner.ctx();
  const keyBal = BigInt(kctx.permission.GasKeyFunctionCall.balance);
  const before = BigInt((await rpc('query', { request_type: 'view_account', finality: 'final', account_id: CONTRACT })).result.amount);
  const { so } = await sh(NEAR_BIN, ['account', 'withdraw-from-gas-key', CONTRACT, owner.pk58, `${(Number(keyBal) / 1e24 - 0.0002).toFixed(6)} NEAR`, 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send']);
  const wtx = (so.match(/Transaction ID: ([A-Za-z0-9]+)/) || [])[1];
  let after = before;
  for (let i = 0; i < 12 && after === before; i++) { after = BigInt((await rpc('query', { request_type: 'view_account', finality: 'final', account_id: CONTRACT })).result.amount); if (after === before) await sleep(2000); }
  if (after <= before) { console.error(`❌ drain failed (cli: ${so.slice(0, 150)})`); process.exit(1); }
  console.log(`✅ drained ${(Number(keyBal) / 1e24).toFixed(4)}Ⓝ back to account ${wtx ? '(tx ' + wtx.slice(0, 10) + '…)' : ''}`);
  PASS.push('drain via WithdrawFromGasKey');
  await v0('revoke drained key (0 burn)', 'revoke_session',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ public_key: ownerPkHex, nonce: n, signature: ownerSig(n, `revoke_session:${ownerPkHex}`), expires_at_sig: EXPIRY.toString() }, ['expires_at_sig']); });
  let gone = false;
  for (let i = 0; i < 10 && !gone; i++) { try { await rpc('query', { request_type: 'view_access_key', finality: 'final', account_id: CONTRACT, public_key: owner.pk58 }); await sleep(1500); } catch (e) { gone = true; } }
  if (!gone) { console.error('❌ key not revoked'); process.exit(1); }
  console.log(`✅ revoked clean — 0 burned`);
  PASS.push('drain → revoke rotation');

  console.log(`\n╔══ v5 FINISHED ════════════════════════════════════════════════`);
  console.log(`║ ALL PASS ✅  ${PASS.length} checks green`);
  for (const t of TXS) console.log(`║   ${t}`);
  console.log(`╚══════════════════════════════════════════════════════════════╝`);
})().catch((e) => { console.error('FATAL', (e.message || e).toString().slice(0, 400)); process.exit(1); });
