// lib.cjs — shared helpers for the nostr-msig testbench
const fs = require('fs');
const path = require('path');
const nearAPI = require('near-api-js');
const bs58 = require('bs58');

const RPC = process.env.BENCH_RPC || 'https://rpc.testnet.fastnear.com';
const NETWORK = 'testnet';
const CRED_DIR = path.join(process.env.HOME || '', '.near-credentials', NETWORK);

const yocto = (n) => (BigInt(Math.round(n * 1e6)) * 10n ** 18n).toString();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function connect(accountId) {
  const cred = JSON.parse(fs.readFileSync(path.join(CRED_DIR, `${accountId}.json`), 'utf8'));
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  await keyStore.setKey(NETWORK, accountId, nearAPI.KeyPair.fromString(cred.private_key));
  return nearAPI.connect({ networkId: NETWORK, nodeUrl: RPC, keyStore });
}

async function rpcQuery(params, rpc = RPC) {
  const r = await (
    await fetch(rpc, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'bench', method: 'query', params }),
    })
  ).json();
  if (r.error) throw new Error(`rpc: ${r.error.message}`);
  return r.result;
}

async function viewContract(contractId, method, args = {}, tries = 6) {
  for (let i = 0; i < tries; i++) {
    try {
      const b64 = Buffer.from(JSON.stringify(args)).toString('base64');
      const r = await rpcQuery({
        request_type: 'call_function',
        finality: 'final',
        account_id: contractId,
        method_name: method,
        args_base64: b64,
      });
      const out = JSON.parse(Buffer.from(r.result).toString('utf8'));
      if (out == null) throw new Error('null view');
      return out;
    } catch (e) {
      if (i === tries - 1) throw e;
      await sleep(1500 * (i + 1));
    }
  }
}

async function accountBalance(accountId) {
  const r = await rpcQuery({ request_type: 'view_account', finality: 'final', account_id: accountId });
  return BigInt(r.amount);
}

// ── bech32 (npub/nsec) ──────────────────────────────────────────────
const B32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const b32polymod = (v) => {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const b of v) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ b;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
  }
  return chk;
};
const b32HrpExpand = (hrp) => [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
const b32CreateChecksum = (hrp, data) => {
  const values = [...b32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const mod = b32polymod(values) ^ 1;
  return [0, 1, 2, 3, 4, 5].map((i) => (mod >> (5 * (5 - i))) & 31);
};
const b32ConvertBits = (bytes, from, to, pad) => {
  let acc = 0, bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const b of bytes) {
    if (b >> from) throw new Error('invalid bech32 byte');
    acc = (acc << from) | b;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) { if (bits) out.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) throw new Error('invalid padding');
  return out;
};
const bech32Encode = (hrp, bytes) => {
  const data = b32ConvertBits(bytes, 8, 5, true);
  const combined = [...data, ...b32CreateChecksum(hrp, data)];
  return hrp + '1' + combined.map((d) => B32[d]).join('');
};
const bech32Decode = (s) => {
  const pos = s.lastIndexOf('1');
  if (pos < 1) throw new Error('bad bech32');
  const hrp = s.slice(0, pos);
  const data = [...s.slice(pos + 1)].map((c) => { const i = B32.indexOf(c); if (i < 0) throw new Error('bad char'); return i; });
  return { hrp, bytes: Buffer.from(b32ConvertBits(data, 5, 8, false)) };
};

const hexToBytes = (h) => Buffer.from(h.length % 2 ? '0' + h : h, 'hex');
const npubFromHex = (hex) => bech32Encode('npub', hexToBytes(hex));
const nsecToHex = (nsec) => {
  const { hrp, bytes } = bech32Decode(nsec);
  if (hrp !== 'nsec' || bytes.length !== 32) throw new Error('not a valid nsec');
  return bytes.toString('hex');
};

module.exports = {
  RPC, NETWORK, CRED_DIR, yocto, sleep,
  connect, rpcQuery, viewContract, accountBalance,
  bech32Encode, bech32Decode, npubFromHex, nsecToHex,
};
