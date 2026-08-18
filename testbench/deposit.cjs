// deposit.cjs — owner-flow deposit into a wallet (propose → approve → execute, +NⓃ attached)
// usage: node deposit.cjs [contract] [wallet] [amount-NEAR=1]
const { schnorr } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const { bytesToHex } = require('@noble/hashes/utils');
const { yocto, sleep, connect, viewContract } = require('./lib.cjs');

const CONTRACT = process.argv[2] || 'bench5wsu.vault.kampy.testnet';
const WALLET = process.argv[3] || 'benchw-6prr';
const AMOUNT = process.argv[4] || '1';

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
  const near = await connect(CONTRACT);
  const acct = await near.account(CONTRACT);
  const send = (method, args, deposit = '0') =>
    acct.functionCall({ contractId: CONTRACT, methodName: method, args, gas: '100000000000000', attachedDeposit: deposit });

  const nextOwnerNonce = async () => {
    const base = await view('get_owner_nonce', {});
    const bm = await view('get_owner_nonce_bitmap', {});
    for (let off = 0; off < 64; off++) if (!(Number(bm) >> off & 1)) return Number(base) + off;
    throw new Error('nonce window full');
  };

  const wst = await view('get_wallet_state', { wallet_name: WALLET });
  const pid = wst.wallet.proposal_index;
  console.log(`wallet ${WALLET}: ${Number(await view('get_wallet_near_balance', { wallet_name: WALLET })) / 1e24} Ⓝ | next proposal #${pid}`);

  // propose (owner nonce, retry on ERR_NONCE)
  let r;
  for (let i = 0; i < 4; i++) {
    const n = await nextOwnerNonce();
    try {
      r = await send('propose', rawArgs({ wallet_name: WALLET, intent_index: 3, param_values: JSON.stringify({ amount: yocto(AMOUNT) }), nonce: n, signature: ownerSig(n, `propose:${WALLET}:${pid}`), expires_at: EXPIRY.toString() }, ['expires_at']));
    } catch (e) { if (i === 3 || !/ERR_NONCE/i.test(e.message || '')) throw e; await sleep(1500); continue; }
    if (!r.status?.Failure) break;
    if (!/ERR_NONCE/.test(JSON.stringify(r.status.Failure))) throw new Error('propose: ' + JSON.stringify(r.status.Failure).slice(0, 160));
    await sleep(1500);
  }
  console.log(`✅ propose Deposit ${AMOUNT}Ⓝ (#${pid})`);

  // approve (nostr)
  const pm = (await view('get_proposal_message', { wallet_name: WALLET, id: pid })).replace(': propose ', ': approve ');
  r = await send('approve', rawArgs({ wallet_name: WALLET, proposal_id: pid, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pm), expires_at: EXPIRY.toString() }, ['expires_at']));
  if (r.status?.Failure) throw new Error('approve: ' + JSON.stringify(r.status.Failure).slice(0, 160));
  console.log(`✅ nostr approve`);

  // execute (owner nonce, +attached NEAR)
  for (let i = 0; i < 4; i++) {
    const n = await nextOwnerNonce();
    try {
      r = await send('execute', rawArgs({ wallet_name: WALLET, proposal_id: pid, nonce: n, signature: ownerSig(n, `execute:${WALLET}:${pid}`), expires_at: EXPIRY.toString() }, ['expires_at']), yocto(AMOUNT));
    } catch (e) { if (i === 3 || !/ERR_NONCE/i.test(e.message || '')) throw e; await sleep(1500); continue; }
    if (!r.status?.Failure) break;
    if (!/ERR_NONCE/.test(JSON.stringify(r.status.Failure))) throw new Error('execute: ' + JSON.stringify(r.status.Failure).slice(0, 160));
    await sleep(1500);
  }
  console.log(`✅ execute Deposit (+${AMOUNT}Ⓝ attached)`);

  const bal = await view('get_wallet_near_balance', { wallet_name: WALLET });
  console.log(`wallet balance now: ${Number(bal) / 1e24} Ⓝ`);
})().catch((e) => { console.error('FATAL', (e.message || e).toString().slice(0, 400)); process.exit(1); });
