// v2-minimal: init → create_wallet → (nonce error is fine) — the schnorr question is create_wallet
const ROOT = '/Users/asil/.openclaw/workspace';
const { schnorr } = require(ROOT + '/outlayer-wallet/node_modules/@noble/curves/secp256k1');
const { sha256 } = require(ROOT + '/outlayer-wallet/node_modules/@noble/hashes/sha256');
const { bytesToHex } = require(ROOT + '/outlayer-wallet/node_modules/@noble/hashes/utils');
const nearAPI = require(ROOT + '/node_modules/near-api-js');
const fs = require('fs');
const CONTRACT = 'msigchk.passkey-wallet-test.testnet';
const RPC = 'https://rpc.testnet.fastnear.com';
const NSEC = sha256(new TextEncoder().encode('nostr-msig-e2e-test-v1'));
const NPubHex = bytesToHex(schnorr.getPublicKey(NSEC));
const EXPIRY = (BigInt(Math.floor(Date.now() / 1000)) + 7200n) * 1_000_000_000n;
const schnorrSign = (m) => bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(m)), NSEC));
// v2 format: nonce is CONTRACT-READ; after fresh init owner_nonce=0 → nonce 0
const ownerSigV2 = (nonce, action) => schnorrSign(`expires ${EXPIRY}.000000000: ${action} | nonce: ${nonce} | contract: owner`);
const yocto = (n) => (BigInt(Math.round(n * 1e6)) * 10n ** 18n).toString();

(async () => {
  const cred = JSON.parse(fs.readFileSync(`${process.env.HOME}/.near-credentials/testnet/${CONTRACT}.json`, 'utf8'));
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  await keyStore.setKey('testnet', CONTRACT, nearAPI.KeyPair.fromString(cred.private_key));
  const near = await nearAPI.connect({ networkId: 'testnet', nodeUrl: RPC, keyStore });
  const acct = await near.account(CONTRACT);
  const raw = (obj) => Buffer.from(JSON.stringify(obj, (k, v) => typeof v === 'bigint' ? v.toString() : v));
  const tryCall = async (label, method, args, deposit = '0') => {
    try {
      const r = await acct.functionCall({ contractId: CONTRACT, methodName: method, args: raw(args), gas: '50000000000000', attachedDeposit: deposit });
      const ok = r.status?.SuccessValue !== undefined;
      console.log(ok ? `✅ ${label}` : `❌ ${label} ${JSON.stringify(r.status).slice(0, 140)}`);
      return ok;
    } catch (e) {
      const m = (e.message || '').match(/panicked: [^"\\]+|ERR_[A-Z_]+/) || [(e.message || '').slice(0, 120)];
      console.log(`❌ ${label} — ${m[0]}`);
      return false;
    }
  };
  // fresh account → init v2
  let ok = await tryCall('init v2(owner_npub)', 'new', { owner_npub: NPubHex });
  if (!ok) { console.log('(already initialized — continuing)'); }
  // create_wallet with v2 message (nonce 0)
  await tryCall('create_wallet v2 sig', 'create_wallet',
    { name: 't1', signature: ownerSigV2(0, 'create_wallet:t1'), expires_at: Number(EXPIRY) }, yocto(0.5));
})().catch(e => console.error('FATAL', (e.message || '').slice(0, 200)));
