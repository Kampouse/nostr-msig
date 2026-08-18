/**
 * v1.cjs — TransactionV1 (NEP-611 gas keys) for JavaScript.
 *
 * near-api-js (even 7.3.1) only encodes V0 transactions; this module
 * hand-rolls the borsh layout from near-primitives 0.37.x:
 *
 *   Transaction          = V0(raw fields) | V1( u8(1) + TransactionV1 )
 *   TransactionV1        = signerId: string, publicKey, nonce: TransactionNonce,
 *                          receiverId: string, blockHash: [u8;32],
 *                          actions: Vec<Action>, nonce_mode: NonceMode(u8)
 *   TransactionNonce     = Nonce{ u8(0), nonce: u64 }
 *                        | GasKeyNonce{ u8(1), nonce: u64, nonce_index: u16 }
 *   NonceMode            = Monotonic(0, default) | Strict(1)
 *   SignedTransaction    = transaction: Transaction, signature: Signature
 *   Signature (ed25519)  = u8(0) + 64 bytes
 *   tx hash for signing  = sha256(borsh(Transaction))
 *
 * Usage:
 *   const { buildV1, broadcast } = require('./v1.cjs');
 *   const { signedBase64, txHash } = buildV1({ signerId, secretKey58, receiverId,
 *     baseNonce, nonceIndex, blockHashB58, actions: [{ functionCall: {...} }] });
 */

// ── minimal borsh writer ────────────────────────────────────────────
class B {
  constructor() { this.b = []; }
  u8(n)  { this.b.push(n & 0xff); return this; }
  u16(n) { const dv = new DataView(new ArrayBuffer(2)); dv.setUint16(0, Number(n), true); this.b.push(...new Uint8Array(dv.buffer)); return this; }
  u32(n) { const dv = new DataView(new ArrayBuffer(4)); dv.setUint32(0, Number(n), true); this.b.push(...new Uint8Array(dv.buffer)); return this; }
  u64(n) { const dv = new DataView(new ArrayBuffer(8)); dv.setBigUint64(0, BigInt(n), true); this.b.push(...new Uint8Array(dv.buffer)); return this; }
  u128(n){ const v = BigInt(n); const dv = new DataView(new ArrayBuffer(16));
           for (let i = 0; i < 16; i++) dv.setUint8(i, Number((v >> BigInt(8 * i)) & 0xffn));
           this.b.push(...new Uint8Array(dv.buffer)); return this; }
  bytes(a){ this.b.push(...a); return this; }
  string(s){ const u = new TextEncoder().encode(s); this.u32(u.length).bytes(u); return this; }
  array(items, fn){ this.u32(items.length); for (const it of items) fn(this, it); return this; }
  out() { return new Uint8Array(this.b); }
}

// ── key helpers (base58 ed25519, near-format) ──────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const b58decode = (s) => { let n = 0n; for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error('bad b58'); n = n * 58n + BigInt(i); } const hex = n.toString(16).padStart(Math.ceil(n.toString(16).length / 2) * 2, '0'); const bytes = new Uint8Array((hex.match(/../g) || []).map((h) => parseInt(h, 16))); let z = 0; for (const c of s) { if (c === '1') z++; else break; } const out = new Uint8Array(z + bytes.length); out.set(bytes, z); return out; };
const b58encode = (bytes) => { let n = 0n; for (const b of bytes) n = n * 256n + BigInt(b); let s = ''; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; } let z = 0; for (const b of bytes) { if (b === 0) z++; else break; } return '1'.repeat(z) + s; };

// near KeyPair string "ed25519:<b58 64-byte>" → { pk: 32 bytes, sk: 64 bytes }
const parseNearKey = (s) => {
  const raw = b58decode(s.replace(/^ed25519:/, ''));
  if (raw.length !== 64) throw new Error(`expected 64-byte key, got ${raw.length}`);
  return { sk: raw.slice(0, 32), pk: raw.slice(32) };
};

// ── borsh pieces ────────────────────────────────────────────────────
const encodePublicKey = (b, pk32) => b.u8(0).bytes(pk32);
const encodeSignature = (b, sig64) => b.u8(0).bytes(sig64);
const encodeNonce = (b, { baseNonce, nonceIndex }) =>
  b.u8(1).u64(baseNonce).u16(nonceIndex); // GasKeyNonce
const encodeAction = (b, a) => {
  if (a.functionCall) {
    const { methodName, args = {}, gas, depositYN = '0' } = a.functionCall;
    const argBytes = new TextEncoder().encode(JSON.stringify(args));
    return b.u8(2) // Action::FunctionCall
      .string(methodName).u32(argBytes.length).bytes(argBytes)
      .u64(gas).u128(depositYN);
  }
  if (a.transfer) {
    return b.u8(3).u128(a.transfer.depositYN); // Action::Transfer
  }
  throw new Error(`unsupported action: ${Object.keys(a)}`);
};

/**
 * Build a signed TransactionV1.
 * @returns {{signedBase64: string, txHash: string, txBytes: Uint8Array}}
 */
const buildV1 = ({ signerId, secretKey /* near-format string or 32-byte seed */, receiverId, baseNonce, nonceIndex = 0, blockHash /* b58 */, actions, nonceMode = 0 }) => {
  const ed = require('@noble/ed25519');
  const { sha256 } = require('@noble/hashes/sha256');
  const { bytesToHex } = require('@noble/hashes/utils');
  const key = typeof secretKey === 'string' ? parseNearKey(secretKey) : { sk: secretKey };
  const seed = key.sk;
  const pk = ed.getPublicKey(seed);

  const body = new B();
  body.string(signerId);
  encodePublicKey(body, pk);
  encodeNonce(body, { baseNonce, nonceIndex });
  body.string(receiverId);
  body.bytes(b58decode(blockHash));
  body.array(actions, encodeAction);
  body.u8(nonceMode);

  const txBytes = new B().u8(1).bytes(body.out()).out(); // Transaction::V1
  const digest = sha256(txBytes);
  const sig = ed.sign(digest, seed); // 64 bytes
  const signed = new B().bytes(txBytes); // transaction
  encodeSignature(signed, sig); // signature
  return { signedBase64: Buffer.from(signed.out()).toString('base64'), txHash: bytesToHex(digest), txBytes, publicKeyHex: Buffer.from(pk).toString('hex') };
};

// ── RPC ─────────────────────────────────────────────────────────────
// noble/ed25519 v2.3 sync mode needs sha512 wired in (hook lives on `etc`)
const ed25519 = require('@noble/ed25519');
const { sha512 } = require('@noble/hashes/sha512');
const sha512Sync = (...m) => sha512(ed25519.etc?.concatBytes ? ed25519.etc.concatBytes(...m) : Buffer.concat(m));
if (ed25519.etc) ed25519.etc.sha512Sync = sha512Sync;
if (ed25519.utils) ed25519.utils.sha512Sync = sha512Sync; // v2.0/2.1 compat

const rpc = async (method, params, url = process.env.BENCH_RPC || 'https://rpc.testnet.fastnear.com') =>
  (await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 'v1', method, params }) })).json();

/** broadcast a signed V1 tx, wait for commit */
const broadcast = async (signedBase64) => {
  const r = await rpc('broadcast_tx_commit', [signedBase64]);
  if (r.error) throw new Error(`rpc: ${r.error.message}: ${JSON.stringify(r.error.data || '').slice(0, 200)}`);
  return r.result;
};

/** current lane nonces + block hash for a gas key (uses the view_gas_key_nonces query) */
const keyContext = async (accountId, publicKey58) => {
  const r = await rpc('query', { request_type: 'view_gas_key_nonces', finality: 'final', account_id: accountId, public_key: publicKey58 });
  if (r.error) throw new Error(`keyContext: ${JSON.stringify(r.error).slice(0, 200)}`);
  const perm = await rpc('query', { request_type: 'view_access_key', finality: 'final', account_id: accountId, public_key: publicKey58 });
  if (perm.error) throw new Error(`keyContext: ${JSON.stringify(perm.error).slice(0, 200)}`);
  return {
    nonces: r.result.nonces,               // per-lane current nonces
    blockHash: r.result.block_hash,
    permission: perm.result.permission,     // GasKeyFunctionCall { balance, ... }
  };
};

module.exports = { buildV1, broadcast, keyContext, rpc, B, parseNearKey, b58decode, b58encode };
