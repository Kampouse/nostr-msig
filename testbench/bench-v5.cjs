/**
 * bench-v5.cjs — v5 verification: widened session-key methods + drain-then-revoke.
 *
 * FLAGSHIP: full governance flow (propose → approve → execute) submitted
 * as pure-JS TransactionV1 txs signed ONLY by session gas keys — no CLI,
 * no relayer, no full-access key in the loop. Includes agent-npub
 * delegation (a dedicated agent npub approves via its own scoped key),
 * method-allowlist rejection, v4 default-methods compat, and the
 * NEP-611 drain-then-revoke rotation.
 *
 * Env: BENCH_CONTRACT (required), BENCH_RECIPIENT (default vault.kampy.testnet),
 *      BENCH_WALLET (default benchw-<rand>), BENCH_OWNER_PASSPHRASE (default)
 */
const { schnorr } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const { bytesToHex } = require('@noble/hashes/utils');
const nearAPI = require('near-api-js');
const { execFile } = require('child_process');
const { yocto, sleep, connect, viewContract, npubFromHex } = require('./lib.cjs');
const { buildV1, broadcast, keyContext, rpc } = require('./v1.cjs');

const CONTRACT = process.env.BENCH_CONTRACT;
if (!CONTRACT) { console.error('BENCH_CONTRACT required'); process.exit(1); }
const NEAR_BIN = process.env.NEAR_BIN || process.env.HOME + '/.cargo/bin/near';
const RECIPIENT = process.env.BENCH_RECIPIENT || 'vault.kampy.testnet';
const WALLET = process.env.BENCH_WALLET || 'benchw-' + (Date.now() % 1e6).toString(36);

const NSEC = Buffer.from(bytesToHex(sha256(new TextEncoder().encode(process.env.BENCH_OWNER_PASSPHRASE || 'nostr-msig-bench-v1'))), 'hex');
const NPubHex = bytesToHex(schnorr.getPublicKey(NSEC));
const AGENT_NSEC = Buffer.from(bytesToHex(sha256(new TextEncoder().encode('agent-' + (process.env.BENCH_OWNER_PASSPHRASE || 'nostr-msig-bench-v1')))), 'hex');
const AGENT_NPubHex = bytesToHex(schnorr.getPublicKey(AGENT_NSEC));

const EXPIRY = (BigInt(Math.floor(Date.now() / 1000)) + 7200n) * 1_000_000_000n;
const schnorrSign = (m, sk = NSEC) => bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(m)), sk));
const ownerSig = (nonce, action) => schnorrSign(`expires ${EXPIRY}.000000000: ${action} | nonce: ${nonce} | contract: ${CONTRACT}`);
const depHash = (def) => bytesToHex(sha256(new TextEncoder().encode(def)));
const rawArgs = (obj, big = []) => JSON.parse(Buffer.from(JSON.stringify(
  JSON.parse('{' + Object.entries(obj).map(([k, v]) => big.includes(k) ? `"${k}":${v}` : `"${k}":${JSON.stringify(v)}`).join(',') + '}'),
  (k, v) => typeof v === 'bigint' ? v.toString() : v)));

const TXS = []; const PASS = [];
const sh = (cmd, args) => new Promise((res) => execFile(cmd, args, { maxBuffer: 12e6 }, (err, stdout, stderr) => res({ err, stdout: stdout.replace(/\x1b\[[0-9;]*m/g, ''), stderr: stderr.replace(/\x1b\[[0-9;]*m/g, '') })));
const view = async (method, args = {}, tries = 6) => {
  for (let i = 0; i < tries; i++) {
    try { return await viewContract(CONTRACT, method, args); } catch (e) { if (i === tries - 1) throw e; await sleep(1500 * (i + 1)); }
  }
};

// V0 submitter with arg BUILDER (fresh owner nonce each attempt)
const makeV0 = (acct) => async (label, method, build, { deposit = '0', mustFail = null } = {}) => {
  for (let i = 0; i < 6; i++) {
    try {
      const r = await acct.functionCall({ contractId: CONTRACT, methodName: method, args: await build(), gas: '100000000000000', attachedDeposit: deposit });
      const f = r.status?.Failure ? JSON.stringify(r.status.Failure) : null;
      if (mustFail) {
        if (f && f.includes(mustFail)) { console.log(`🛡️  ${label} → correctly rejected (${mustFail})`); PASS.push(label); return r; }
        throw new Error(`expected ${mustFail}, got ${f || 'success'}`);
      }
      if (f) throw new Error(f.slice(0, 160));
      console.log(`✅ ${label}`); PASS.push(label); return r;
    } catch (e) {
      const m = e.message || '';
      if (mustFail && m.includes(mustFail)) { console.log(`🛡️  ${label} → correctly rejected (${mustFail})`); PASS.push(label); return null; }
      if (i === 5 || !/ERR_NONCE|429|timeout|FetchError/i.test(m)) throw new Error(`${label}: ${m.slice(0, 180)}`);
      await sleep(1500);
    }
  }
};

// V1 gas-key submitter (pure JS) with lane + owner-nonce retry
const makeGasClient = (nearKeypair) => {
  const pk58 = nearKeypair.publicKey.toString();
  let lane = null, blockHash = null;
  const ctx = async () => {
    for (let i = 0; i < 12; i++) {
      try {
        const c = await keyContext(CONTRACT, pk58);
        if (c.permission?.GasKeyFunctionCall) { lane = BigInt(c.nonces[0]); blockHash = c.blockHash; return c; }
      } catch (e) {}
      await sleep(1500);
    }
    throw new Error(`gas key ${pk58.slice(0, 16)} not visible`);
  };
  const call = async (label, method, build, { mustFail = null } = {}) => {
    for (let attempt = 0; attempt < 6; attempt++) {
      const { signedBase64 } = buildV1({
        signerId: CONTRACT, secretKey: nearKeypair.toString(), receiverId: CONTRACT,
        baseNonce: lane + 1n, nonceIndex: 0, blockHash,
        actions: [{ functionCall: { methodName: method, args: await build(), gas: 100_000_000_000_000n } }],
      });
      let res;
      try { res = await broadcast(signedBase64); }
      catch (e) {
        const m = e.message || '';
        if (/InvalidNonce/i.test(m)) { const c = await ctx(); lane = BigInt(c.nonces[0]); blockHash = c.blockHash; await sleep(1200); continue; }
        if (mustFail && (m.includes(mustFail) || /does not have access|GasKey/i.test(m) && mustFail === 'PROTOCOL_SCOPE')) { console.log(`🛡️  ${label} → correctly rejected (protocol)`); PASS.push(label); return; }
        throw new Error(`${label}: ${m.slice(0, 200)}`);
      }
      lane += 1n;
      const errs = (res.receipts_outcome || []).map((o) => o.outcome.status?.Failure).filter(Boolean);
      if (errs.length) {
        const f = JSON.stringify(errs[0]);
        if (mustFail && f.includes(mustFail)) { console.log(`🛡️  ${label} → correctly rejected (${mustFail})`); PASS.push(label); return; }
        if ((/InvalidNonce/i.test(f) || /ERR_NONCE/i.test(f)) && attempt < 5) { const c = await ctx(); lane = BigInt(c.nonces[0]); blockHash = c.blockHash; await sleep(1200); continue; }
        throw new Error(`${label}: receipt failure ${f.slice(0, 200)}`);
      }
      TXS.push(`${method} (V1 gas-key): ${res.transaction_outcome.id}`);
      if (mustFail) throw new Error(`${label}: expected ${mustFail}, got success`);
      console.log(`✅ ${label}`); PASS.push(label);
      return res;
    }
    throw new Error(`${label}: nonce retries exhausted`);
  };
  return { ctx, call, pk58 };
};

(async () => {
  const near = await connect(CONTRACT);
  const acct = await near.account(CONTRACT);
  const v0 = makeV0(acct);
  console.log(`╔══ nostr-msig v5 TESTBENCH ═══════════════════════════════════╗`);
  console.log(`║ contract: ${CONTRACT}`);
  console.log(`║ wallet: ${WALLET} | owner npub ${npubFromHex(NPubHex).slice(0, 20)}…`);
  console.log(`║ agent npub ${npubFromHex(AGENT_NPubHex).slice(0, 20)}… (dedicated approver)`);
  console.log(`╚══════════════════════════════════════════════════════════════╝`);

  const version = await view('get_version', {});
  if (version !== 5) { console.error(`❌ expected v5, got ${version}`); process.exit(1); }
  console.log(`✅ get_version = 5`);

  const nextOwnerNonce = async () => {
    const base = await view('get_owner_nonce', {});
    const bm = await view('get_owner_nonce_bitmap', {});
    for (let off = 0; off < 64; off++) if (!(Number(bm) >> off & 1)) return Number(base) + off;
    throw new Error('nonce window full');
  };

  // ── 1. bootstrap (V0): wallet, agent intent, deposit ──────────────
  await v0(`create_wallet ${WALLET} (+0.5Ⓝ)`, 'create_wallet',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ name: WALLET, nonce: n, signature: ownerSig(n, `create_wallet:${WALLET}`), expires_at: EXPIRY.toString() }, ['expires_at']); },
    { deposit: yocto(0.5) });

  const agentIntent = JSON.stringify({
    wallet_name: WALLET, index: 0, intent_type: 'Transfer', name: 'AgentTransfer',
    template: 'transfer {amount} yoctoNEAR to {recipient}',
    proposers: [], approvers: [], nostr_approvers: [AGENT_NPubHex],
    approval_threshold: 1, cancellation_threshold: 1, timelock_seconds: 0,
    params: [{ name: 'amount', param_type: 'U128', max_value: yocto(1) },
             { name: 'recipient', param_type: 'AccountId', max_value: null }],
    execution_gas_tgas: 50, active: true, active_proposal_count: 0,
  });
  const ah = depHash(agentIntent);
  await v0('propose AddIntent(AgentTransfer, agent-approved)', 'propose',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, intent_index: 0, param_values: JSON.stringify({ hash: ah, definition: agentIntent }), nonce: n, signature: ownerSig(n, `propose:${WALLET}:0`), expires_at: EXPIRY.toString() }, ['expires_at']); });
  let pm = (await view('get_proposal_message', { wallet_name: WALLET, id: 0 })).replace(': propose ', ': approve ');
  await v0('nostr approve AddIntent(AgentTransfer) [owner-only meta]', 'approve',
    async () => rawArgs({ wallet_name: WALLET, proposal_id: 0, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pm), expires_at: EXPIRY.toString() }, ['expires_at']));
  await v0('execute AddIntent(AgentTransfer) → intent #3', 'execute',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: 0, nonce: n, signature: ownerSig(n, `execute:${WALLET}:0`), expires_at: EXPIRY.toString() }, ['expires_at']); });

  // Deposit intent (template) → lands at #4
  const depositIntent = JSON.stringify({
    wallet_name: WALLET, index: 0, intent_type: 'Deposit', name: 'Deposit NEAR',
    template: 'deposit NEAR to wallet',
    proposers: [], approvers: [], nostr_approvers: [NPubHex],
    approval_threshold: 1, cancellation_threshold: 1, timelock_seconds: 0,
    params: [{ name: 'amount', param_type: 'U128', max_value: null }],
    execution_gas_tgas: 50, active: true, active_proposal_count: 0,
  });
  const dh = depHash(depositIntent);
  await v0('propose AddIntent(Deposit)', 'propose',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, intent_index: 0, param_values: JSON.stringify({ hash: dh, definition: depositIntent }), nonce: n, signature: ownerSig(n, `propose:${WALLET}:1`), expires_at: EXPIRY.toString() }, ['expires_at']); });
  let pm1 = (await view('get_proposal_message', { wallet_name: WALLET, id: 1 })).replace(': propose ', ': approve ');
  await v0('nostr approve AddIntent(Deposit)', 'approve',
    async () => rawArgs({ wallet_name: WALLET, proposal_id: 1, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pm1), expires_at: EXPIRY.toString() }, ['expires_at']));
  await v0('execute AddIntent(Deposit) → intent #4', 'execute',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: 1, nonce: n, signature: ownerSig(n, `execute:${WALLET}:1`), expires_at: EXPIRY.toString() }, ['expires_at']); });

  const wst = await view('get_wallet_state', { wallet_name: WALLET });
  const depPid = wst.wallet.proposal_index;
  await v0(`propose Deposit 0.55Ⓝ (#${depPid})`, 'propose',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, intent_index: 4, param_values: JSON.stringify({ amount: yocto(0.55) }), nonce: n, signature: ownerSig(n, `propose:${WALLET}:${depPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });
  pm = (await view('get_proposal_message', { wallet_name: WALLET, id: depPid })).replace(': propose ', ': approve ');
  await v0('nostr approve Deposit', 'approve',
    async () => rawArgs({ wallet_name: WALLET, proposal_id: depPid, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pm), expires_at: EXPIRY.toString() }, ['expires_at']));
  await v0('execute Deposit (+0.55Ⓝ)', 'execute',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: depPid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${depPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); },
    { deposit: yocto(0.55) });

  // ── 2. session keys: widened + agent-scoped + default + bogus ─────
  const ownerKp = nearAPI.KeyPair.fromRandom('ed25519');
  const agentKp = nearAPI.KeyPair.fromRandom('ed25519');
  const defKp = nearAPI.KeyPair.fromRandom('ed25519');
  const ownerPkHex = Buffer.from(ownerKp.publicKey.data).toString('hex');
  const agentPkHex = Buffer.from(agentKp.publicKey.data).toString('hex');
  const defPkHex = Buffer.from(defKp.publicKey.data).toString('hex');
  const METHODS = ['submit_action', 'session_ping', 'propose', 'approve', 'execute'];
  const expMs = () => Number(BigInt(Date.now() + 3600_000) * 1_000_000n);
  const addBuild = (pkHex, nn, wallet, label, gas, methods) => async () => {
    const n = await nextOwnerNonce();
    const a = { public_key: pkHex, num_nonces: nn, expires_at: expMs(), wallet, label, initial_gas: yocto(gas), nonce: n, signature: ownerSig(n, `add_session_key:${pkHex}`), expires_at_sig: EXPIRY.toString() };
    if (methods) a.methods = methods;
    return rawArgs(a, ['expires_at', 'expires_at_sig']);
  };

  await v0('add_session_key(bogus methods) → rejected', 'add_session_key',
    addBuild(ownerPkHex, 2, WALLET, 'bogus', 0.1, ['create_wallet']),
    { mustFail: 'ERR_SESSION_METHOD_NOT_ALLOWED' });
  await v0(`add_session_key owner-transport (${METHODS.length} methods)`, 'add_session_key',
    addBuild(ownerPkHex, 2, WALLET, 'v5-owner', 0.2, METHODS));
  await v0('add_session_key agent (approve-scoped)', 'add_session_key',
    addBuild(agentPkHex, 1, WALLET, 'v5-agent', 0.1, ['approve', 'session_ping']));
  await v0('add_session_key default (v4 compat)', 'add_session_key',
    addBuild(defPkHex, 1, WALLET, 'v5-default', 0.01, null));

  const owner = makeGasClient(ownerKp);
  const agent = makeGasClient(agentKp);
  const octx = await owner.ctx();
  const onChainMethods = octx.permission.GasKeyFunctionCall.method_names;
  const want = new Set(METHODS);
  if (onChainMethods.length !== want.size || onChainMethods.some((m) => !want.has(m))) {
    console.error(`❌ owner key methods mismatch: ${onChainMethods}`); process.exit(1);
  }
  console.log(`✅ on-chain method_names = [${onChainMethods.join(', ')}]`);
  PASS.push('widened methods visible on-chain');
  const actx = await agent.ctx();
  if (JSON.stringify(actx.permission.GasKeyFunctionCall.method_names) !== JSON.stringify(['approve', 'session_ping'])) {
    console.error(`❌ agent key methods: ${actx.permission.GasKeyFunctionCall.method_names}`); process.exit(1);
  }
  console.log(`✅ agent key scoped to [approve, session_ping]`);
  PASS.push('agent key scoped');
  let defMethods = null;
  for (let i = 0; i < 10 && !defMethods; i++) {
    try {
      const r = await rpc('query', { request_type: 'view_access_key', finality: 'final', account_id: CONTRACT, public_key: defKp.publicKey.toString() });
      defMethods = r.result?.permission?.GasKeyFunctionCall?.method_names || null;
    } catch (e) {}
    if (!defMethods) await sleep(1500);
  }
  if (JSON.stringify(defMethods) !== JSON.stringify(['submit_action', 'session_ping'])) {
    console.error(`❌ default methods changed: ${JSON.stringify(defMethods)}`); process.exit(1);
  }
  console.log(`✅ default key scope = [submit_action, session_ping] (v4 compat)`);
  PASS.push('v4 default methods compat');

  // ── 3. FLAGSHIP: governance via gas keys only ─────────────────────
  const wst2 = await view('get_wallet_state', { wallet_name: WALLET });
  const tPid = wst2.wallet.proposal_index;
  const balBefore = BigInt(await view('get_wallet_near_balance', { wallet_name: WALLET }));
  await owner.call(`propose AgentTransfer 0.05Ⓝ (#${tPid}) VIA V1 gas key`, 'propose',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, intent_index: 3, param_values: JSON.stringify({ amount: yocto(0.05), recipient: RECIPIENT }), nonce: n, signature: ownerSig(n, `propose:${WALLET}:${tPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });
  pm = (await view('get_proposal_message', { wallet_name: WALLET, id: tPid })).replace(': propose ', ': approve ');
  await agent.call('AGENT npub approves VIA its own V1 gas key', 'approve',
    async () => rawArgs({ wallet_name: WALLET, proposal_id: tPid, approver_index: 0, pubkey_hex: AGENT_NPubHex, signature: schnorrSign(pm, AGENT_NSEC), expires_at: EXPIRY.toString() }, ['expires_at']));
  await owner.call(`execute AgentTransfer (#${tPid}) VIA V1 gas key`, 'execute',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: tPid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${tPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); });

  let balAfter = balBefore;
  for (let i = 0; i < 10 && balAfter === balBefore; i++) { balAfter = BigInt(await view('get_wallet_near_balance', { wallet_name: WALLET })); if (balAfter === balBefore) await sleep(1500); }
  const spent = balBefore - balAfter;
  if (spent < 50_000_000_000_000_000_000n || spent > 60_000_000_000_000_000_000n) {
    console.error(`❌ wallet delta ${(Number(spent) / 1e24)}Ⓝ — expected ~0.05Ⓝ`); process.exit(1);
  }
  console.log(`   wallet: ${(Number(balBefore) / 1e24).toFixed(4)} → ${(Number(balAfter) / 1e24).toFixed(4)} Ⓝ (−0.05Ⓝ out)`);
  PASS.push('governance via gas keys: funds moved');

  // scope rejection: agent key tries execute (outside its 2 methods)
  await agent.call('agent execute attempt → out of scope', 'execute',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ wallet_name: WALLET, proposal_id: tPid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${tPid}`), expires_at: EXPIRY.toString() }, ['expires_at']); },
    { mustFail: 'PROTOCOL_SCOPE' });

  // ── 4. drain-then-revoke rotation ──────────────────────────────────
  const kctx = await owner.ctx();
  const keyBal = BigInt(kctx.permission.GasKeyFunctionCall.balance);
  const acctBalBefore = BigInt((await rpc('query', { request_type: 'view_account', finality: 'final', account_id: CONTRACT })).result.amount);
  const { stdout } = await sh(NEAR_BIN, ['account', 'withdraw-from-gas-key', CONTRACT, owner.pk58, `${Number(keyBal) / 1e24} NEAR`, 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send']);
  const wtx = (stdout.match(/Transaction ID: ([A-Za-z0-9]+)/) || []).slice(1).find(Boolean);
  if (!wtx) { console.error(`❌ withdraw CLI failed:\n${stdout.slice(0, 400)}`); process.exit(1); }
  TXS.push(`withdraw-from-gas-key: ${wtx}`);
  let acctBalAfter = acctBalBefore;
  for (let i = 0; i < 10 && acctBalAfter === acctBalBefore; i++) { acctBalAfter = BigInt((await rpc('query', { request_type: 'view_account', finality: 'final', account_id: CONTRACT })).result.amount); if (acctBalAfter === acctBalBefore) await sleep(1500); }
  if (acctBalAfter <= acctBalBefore) { console.error('❌ withdraw did not credit account'); process.exit(1); }
  console.log(`✅ drained ${(Number(keyBal) / 1e24).toFixed(6)}Ⓝ back to contract account (tx ${wtx.slice(0, 12)}…)`);
  PASS.push('drain via WithdrawFromGasKey');
  await v0('revoke_session drained key (0 burn)', 'revoke_session',
    async () => { const n = await nextOwnerNonce(); return rawArgs({ public_key: ownerPkHex, nonce: n, signature: ownerSig(n, `revoke_session:${ownerPkHex}`), expires_at_sig: EXPIRY.toString() }, ['expires_at_sig']); });
  let gone = false;
  for (let i = 0; i < 10 && !gone; i++) { try { await rpc('query', { request_type: 'view_access_key', finality: 'final', account_id: CONTRACT, public_key: owner.pk58 }); await sleep(1500); } catch (e) { gone = true; } }
  if (!gone) { console.error('❌ owner key still exists'); process.exit(1); }
  console.log(`✅ key revoked clean — balance recovered, nothing burned`);
  PASS.push('rotate: drain → revoke');

  console.log(`\n╔══ v5 RESULT ══════════════════════════════════════════════════`);
  console.log(`║ ALL PASS ✅  ${PASS.length} v5 checks green on ${CONTRACT}`);
  console.log(`║ relayer-free governance: propose/approve/execute all V1 gas-key txs`);
  console.log(`║ agent delegation: separate npub approved via its own scoped key`);
  console.log(`║ rotation: WithdrawFromGasKey → revoke, 0 burned`);
  console.log(`║ txs:`);
  for (const t of TXS) console.log(`║   ${t}`);
  console.log(`╚══════════════════════════════════════════════════════════════╝`);
})().catch((e) => { console.error('FATAL', (e.message || e).toString().slice(0, 400)); process.exit(1); });
