/** cleanup.cjs — post-proof hygiene: drain + revoke every gas key, verify zero remain. */
const { schnorr } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const { bytesToHex } = require('@noble/hashes/utils');
const { execFile } = require('child_process');
const fs = require('fs');
const { sleep, connect } = require('./lib.cjs');

const CONTRACT = 'benchv5.vault.kampy.testnet';
const NEAR_BIN = process.env.HOME + '/.cargo/bin/near';
const NSEC = Buffer.from(bytesToHex(sha256(new TextEncoder().encode('nostr-msig-bench-v1'))), 'hex');
const EXPIRY = (BigInt(Math.floor(Date.now() / 1000)) + 7200n) * 1_000_000_000n;
const schnorrSign = (m) => bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(m)), NSEC));
const sh = (cmd, args) => new Promise((res) => execFile(cmd, args, { maxBuffer: 12e6 }, (e, so, se) => res(so || '')));
const V = { revoked: [], drained: 0 };
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const b58toHex = (s) => {
  let n = 0n;
  for (const c of s) n = n * 58n + BigInt(B58.indexOf(c));
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  for (const c of s) { if (c === '1') h = '00' + h; else break; }
  return h;
};
const rpc = (method, params) => fetch('https://rpc.testnet.near.org', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 'x', method, params }) }).then(r => r.json());

(async () => {
  const near = await connect(CONTRACT);
  const acct = await near.account(CONTRACT);
  const call = async (m, a = {}) => JSON.parse(Buffer.from((await rpc('query', { request_type: 'call_function', finality: 'final', account_id: CONTRACT, method_name: m, args_base64: Buffer.from(JSON.stringify(a)).toString('base64') })).result.result).toString());
  const nextNonce = async () => {
    const base = Number(await call('get_owner_nonce'));
    const bm = await call('get_owner_nonce_bitmap');
    for (let off = 0; off < 64; off++) if (!(Number(bm) >> off & 1)) return base + off;
    throw new Error('window full');
  };
  const ownerSig = (nonce, action) => schnorrSign(`expires ${EXPIRY}.000000000: ${action} | nonce: ${nonce} | contract: ${CONTRACT}`);

  for (let round = 0; round < 3; round++) {
    const keys = (await rpc('query', { request_type: 'view_access_key_list', finality: 'final', account_id: CONTRACT })).result.keys.filter(k => k.access_key.permission.GasKeyFunctionCall);
    if (!keys.length) break;
    for (const k of keys) {
      const pk58 = k.public_key;
      const bal = Number(k.access_key.permission.GasKeyFunctionCall.balance) / 1e24;
      if (bal > 0.005) {
        const amt = (bal - 0.0004).toFixed(4);
        await sh(NEAR_BIN, ['account', 'withdraw-from-gas-key', CONTRACT, pk58, amt + ' NEAR', 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send']);
        V.drained += Number(amt);
        await sleep(2500);
      }
      const pkHex = b58toHex(pk58.replace('ed25519:', ''));
      for (let a = 0; a < 4; a++) {
        try {
          const n = await nextNonce();
          const argsJson = `{"public_key":"${pkHex}","nonce":${n},"signature":"${ownerSig(n, `revoke_session:${pkHex}`)}","expires_at_sig":${EXPIRY}}`;
          await acct.functionCall({ contractId: CONTRACT, methodName: 'revoke_session', args: Buffer.from(argsJson), gas: '100000000000000' });
          V.revoked.push(pk58.slice(8, 18));
          break;
        } catch (e) { if (a === 3) throw e; await sleep(2000); }
      }
      await sleep(1200);
    }
  }
  await sleep(4000);
  const left = (await rpc('query', { request_type: 'view_access_key_list', finality: 'final', account_id: CONTRACT })).result.keys.filter(k => k.access_key.permission.GasKeyFunctionCall);
  V.gasKeysLeft = left.length;
  V.ok = left.length === 0;
  console.log('revoked', V.revoked.length, '| drained', V.drained.toFixed(3), '| left', left.length);
})().catch(e => { V.ok = false; V.error = String(e.message || e).slice(0, 250); console.error('FATAL', V.error); })
  .finally(() => { fs.writeFileSync(__dirname + '/cleanup-verdict.json', JSON.stringify(V, null, 2)); process.exit(V.ok ? 0 : 1); });
