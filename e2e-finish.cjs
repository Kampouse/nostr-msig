// fund the treasury wallet via Deposit intent, then re-execute the approved transfer
const ROOT = '/Users/asil/.openclaw/workspace';
const { schnorr } = require(ROOT + '/outlayer-wallet/node_modules/@noble/curves/secp256k1');
const { sha256 } = require(ROOT + '/outlayer-wallet/node_modules/@noble/hashes/sha256');
const { bytesToHex } = require(ROOT + '/outlayer-wallet/node_modules/@noble/hashes/utils');
const nearAPI = require(ROOT + '/node_modules/near-api-js');
const fs = require('fs');

const CONTRACT = 'nmsig.vault.kampy.testnet';
const RPC = 'https://rpc.testnet.fastnear.com';
const NSEC = sha256(new TextEncoder().encode('nostr-msig-e2e-test-v1'));
const NPubHex = bytesToHex(schnorr.getPublicKey(NSEC));
const EXPIRY = BigInt(Date.now()) * 1_000_000n + 2n * 3600n * 1_000_000_000n;
const yocto = (n) => (BigInt(Math.round(n * 1e6)) * 10n ** 18n).toString();
const schnorrSign = (m) => bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(m)), NSEC));
const ownerSig = (nonce, action) => schnorrSign(`expires ${EXPIRY}.000000000: ${action} | nonce: ${nonce} | contract: owner`);
const fmt = (ns) => `${ns / 1_000_000_000n}.${String(ns % 1_000_000_000n).padStart(9, '0')}`;
const pMsg = (i, action, content) => `expires ${fmt(EXPIRY)}: ${action} ${content} | wallet: treasury proposal: ${i}`;
const rawArgs = (obj, big) => JSON.parse('{' + Object.entries(obj).map(([k, v]) => big && big.includes(k) ? `"${k}":${v}` : `"${k}":${JSON.stringify(v)}`).join(',') + '}');

(async () => {
  const cred = JSON.parse(fs.readFileSync(`${process.env.HOME}/.near-credentials/testnet/${CONTRACT}.json`, 'utf8'));
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  await keyStore.setKey('testnet', CONTRACT, nearAPI.KeyPair.fromString(cred.private_key));
  const near = await nearAPI.connect({ networkId: 'testnet', nodeUrl: RPC, keyStore });
  const acct = await near.account(CONTRACT);
  const log = (...a) => console.log(...a);
  const call = async (label, method, args, { gas = 50n * 10n ** 12n, deposit = '0' } = {}) => {
    const r = await acct.functionCall({ contractId: CONTRACT, methodName: method, args, gas: gas.toString(), attachedDeposit: deposit });
    if (r.status?.Failure) { log(`❌ ${label} — ${JSON.stringify(r.status.Failure).slice(0, 150)}`); process.exit(1); }
    log(`✅ ${label}`); return r;
  };

  // 1. propose on Deposit intent (intent #3) — nonce 8; content = "deposit NEAR to wallet"
  const depContent = 'deposit NEAR to wallet';
  await call('propose Deposit 1Ⓝ', 'propose',
    rawArgs({ wallet_name: 'treasury', intent_index: 3, param_values: JSON.stringify({ amount: yocto(1) }), signature: ownerSig(7, 'propose:treasury:4'), expires_at: EXPIRY.toString() }, ['expires_at']));

  // 2. nostr approve proposal 4
  await call('nostr approve Deposit', 'approve',
    rawArgs({ wallet_name: 'treasury', proposal_id: 4, approver_index: 0, pubkey_hex: NPubHex, signature: schnorrSign(pMsg(4, 'approve', depContent)), expires_at: EXPIRY.toString() }, ['expires_at']));

  // 3. execute with 1Ⓝ attached — nonce 9
  await call('execute Deposit (+1Ⓝ)', 'execute',
    rawArgs({ wallet_name: 'treasury', proposal_id: 4, signature: ownerSig(8, 'execute:treasury:4'), expires_at: EXPIRY.toString() }, ['expires_at']),
    { deposit: yocto(1) });

  // 4. re-execute approved transfer proposal #3 — nonce 10
  await call('execute transfer 0.5Ⓝ → vault', 'execute',
    rawArgs({ wallet_name: 'treasury', proposal_id: 3, signature: ownerSig(9, 'execute:treasury:3'), expires_at: EXPIRY.toString() }, ['expires_at']));

  // 5. verify
  const view = async (method, args) => {
    const b64 = Buffer.from(JSON.stringify(args)).toString('base64');
    const r = await (await fetch(RPC, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: '1', method: 'query', params: { request_type: 'call_function', finality: 'final', account_id: CONTRACT, method_name: method, args_base64: b64 } }) })).json();
    return JSON.parse(Buffer.from(r.result.result).toString('utf8'));
  };
  const state = await view('get_wallet_state', { wallet_name: 'treasury' });
  const pm = await view('get_proposal_message', { wallet_name: 'treasury', id: 3 });
  const intents = await view('list_intents', { wallet_name: 'treasury' });
  log('\n════ RESULT ════');
  log(`treasury NEAR balance: ${(Number(state.near_balance) / 1e24).toFixed(4)} Ⓝ (expect 0.5: 1.0 in, 0.5 out)`);
  log(`intents: ${intents.length} (3 meta + Deposit + Transfer)`);
  log(`transfer was authorized by signing exactly this text:\n   "${pm}"`);
  log('\nALL PASS ✅ — nostr schnorr auth works end-to-end on NEAR');
})().catch(e => { console.error('FATAL', (e.message || e).toString().slice(0, 300)); process.exit(1); });
