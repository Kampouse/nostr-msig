/**
 * session-demo.cjs — prove pure-JS TransactionV1 against the live bench contract.
 *
 * 1. owner-signed add_session_key (fresh key, num_nonces=1, 0.2Ⓝ, 2h)
 *    → submitted as a regular V0 tx by the bench account key
 * 2. session_ping signed as the GAS KEY from pure JS (v1.cjs) — no CLI
 * 3. assert: tx committed, output contains "pong", gas-key balance decreased
 *
 * usage: node session-demo.cjs [contract] [wallet]
 *   defaults: bench5wsu.vault.kampy.testnet  benchw-6prr
 */
const { schnorr } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const { bytesToHex } = require('@noble/hashes/utils');
const nearAPI = require('near-api-js');
const fs = require('fs');
const path = require('path');
const { RPC, yocto, sleep, connect, rpcQuery, viewContract } = require('./lib.cjs');
const { buildV1, broadcast, keyContext } = require('./v1.cjs');

const CONTRACT = process.argv[2] || 'bench5wsu.vault.kampy.testnet';
const WALLET = process.argv[3] || 'benchw-6prr';

// owner secret (same resolution as bench.cjs)
const NSEC = Buffer.from(bytesToHex(sha256(new TextEncoder().encode(process.env.BENCH_OWNER_PASSPHRASE || 'nostr-msig-bench-v1'))), 'hex');
const NPubHex = bytesToHex(schnorr.getPublicKey(NSEC));
const EXPIRY = (BigInt(Math.floor(Date.now() / 1000)) + 7200n) * 1_000_000_000n;
const schnorrSign = (m) => bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(m)), NSEC));
const ownerSig = (nonce, action) => schnorrSign(`expires ${EXPIRY}.000000000: ${action} | nonce: ${nonce} | contract: ${CONTRACT}`);
const rawArgs = (obj, big = []) => Buffer.from(JSON.stringify(
  JSON.parse('{' + Object.entries(obj).map(([k, v]) => big.includes(k) ? `"${k}":${v}` : `"${k}":${JSON.stringify(v)}`).join(',') + '}'),
  (k, v) => typeof v === 'bigint' ? v.toString() : v));

const view = async (method, args = {}, tries = 6) => {
  for (let i = 0; i < tries; i++) {
    try { return await viewContract(CONTRACT, method, args); } catch (e) { if (i === tries - 1) throw e; await sleep(1500 * (i + 1)); }
  }
};

(async () => {
  console.log(`contract: ${CONTRACT} | wallet: ${WALLET}`);

  // ── 1. fresh keypair + owner-signed add_session_key (V0 via bench key) ──
  const kp = nearAPI.KeyPair.fromRandom('ed25519');
  const pkHex = Buffer.from(kp.publicKey.data).toString('hex');
  const pk58 = kp.publicKey.toString();

  const near = await connect(CONTRACT);
  const acct = await near.account(CONTRACT);
  const nextOwnerNonce = async () => {
    const base = await view('get_owner_nonce', {});
    const bm = await view('get_owner_nonce_bitmap', {});
    for (let off = 0; off < 64; off++) if (!(Number(bm) >> off & 1)) return Number(base) + off;
    throw new Error('nonce window full');
  };
  const addArgs = async () => {
    const n = await nextOwnerNonce();
    return rawArgs({
      public_key: pkHex, num_nonces: 1,
      expires_at: Number(BigInt(Date.now() + 7200_000) * 1_000_000n),
      wallet: WALLET, label: 'js-v1-demo', initial_gas: yocto(0.2),
      nonce: n, signature: ownerSig(n, `add_session_key:${pkHex}`),
      expires_at_sig: EXPIRY.toString(),
    }, ['expires_at', 'expires_at_sig']);
  };
  let r;
  for (let i = 0; i < 4; i++) {
    try {
      r = await acct.functionCall({ contractId: CONTRACT, methodName: 'add_session_key', args: await addArgs(), gas: '100000000000000', attachedDeposit: '0' });
      if (!r.status?.Failure) break;
    } catch (e) {
      if (i === 3 || !/ERR_NONCE/.test(e.message || '')) throw e;
      await sleep(1500);
    }
  }
  if (r?.status?.Failure) throw new Error('add_session_key failed: ' + JSON.stringify(r.status.Failure).slice(0, 200));
  console.log(`✅ add_session_key ${pkHex.slice(0, 12)}… (num_nonces=1, 0.2Ⓝ, 2h) tx ${r.transaction_outcome.id}`);

  // wait until the gas key is visible with its balance
  let ctx;
  for (let i = 0; i < 12; i++) {
    try {
      ctx = await keyContext(CONTRACT, pk58);
      if (ctx.permission?.GasKeyFunctionCall) break;
    } catch (e) {}
    await sleep(1500);
  }
  if (!ctx?.permission?.GasKeyFunctionCall) throw new Error('gas key never appeared');
  const bal0 = BigInt(ctx.permission.GasKeyFunctionCall.balance);
  const lane0 = BigInt(ctx.nonces[0]);
  console.log(`✅ gas key on-chain: balance ${Number(bal0) / 1e24}Ⓝ, lane0 nonce ${lane0}, block ${ctx.blockHash.slice(0, 12)}…`);

  // ── 2. session_ping as the gas key — pure JS TransactionV1 ──
  const { signedBase64, txHash, publicKeyHex } = buildV1({
    signerId: CONTRACT,
    secretKey: kp.toString(),           // near-format "ed25519:…"
    receiverId: CONTRACT,
    baseNonce: lane0 + 1n,               // monotonic: strictly greater than lane nonce
    nonceIndex: 0,                      // only lane (num_nonces=1)
    blockHash: ctx.blockHash,
    actions: [{ functionCall: { methodName: 'session_ping', args: {}, gas: 50_000_000_000_000n } }],
  });
  if (publicKeyHex !== pkHex) throw new Error('derived pubkey mismatch');
  console.log(`→ signed V1 tx ${txHash.slice(0, 20)}… (${signedBase64.length} b64 chars)`);

  const res = await broadcast(signedBase64);
  const out = Buffer.from(res.status?.SuccessValue || '', 'base64').toString('utf8');
  const errs = (res.receipts_outcome || []).map((o) => o.outcome.status?.Failure).filter(Boolean);
  if (errs.length) throw new Error('receipt failed: ' + JSON.stringify(errs[0]).slice(0, 300));
  if (!/pong/.test(out)) throw new Error(`expected pong, got: ${out.slice(0, 120)}`);
  console.log(`✅ session_ping VIA PURE-JS V1 → ${out}`);
  console.log(`   explorer: https://explorer.testnet.near.org/transactions/${res.transaction_outcome.id}`);

  // ── 3. gas balance decreased ──
  let bal1 = bal0;
  for (let i = 0; i < 10 && bal1 === bal0; i++) {
    const c = await keyContext(CONTRACT, pk58).catch(() => null);
    if (c) bal1 = BigInt(c.permission.GasKeyFunctionCall.balance);
    if (bal1 === bal0) await sleep(1500);
  }
  console.log(`✅ gas-key balance: ${Number(bal0) / 1e24} → ${Number(bal1) / 1e24} Ⓝ (spent ${(Number(bal0 - bal1) / 1e24).toFixed(8)})`);
  if (bal1 >= bal0) throw new Error('balance did not decrease');

  console.log(`\n🎉 JS TransactionV1 works — no CLI, no relayer, no near-account wallet.`);
  console.log(`   session key (keep for the web client): ${kp.toString().slice(0, 20)}… saved to bench-session.json`);
  fs.writeFileSync(path.join(__dirname, 'bench-session.json'), JSON.stringify({ contract: CONTRACT, wallet: WALLET, pk58, secret: kp.toString() }, null, 2));
})().catch((e) => { console.error('FATAL', (e.message || e).toString().slice(0, 400)); process.exit(1); });
