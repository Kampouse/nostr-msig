// deploy.cjs — direct wasm deploy via near-api-js (no near-cli artifact cache)
// usage: node deploy.cjs <account> <wasm-path>
const ROOT = '/Users/asil/.openclaw/workspace';
const nearAPI = require(ROOT + '/node_modules/near-api-js');
const fs = require('fs');
const crypto = require('crypto');

const [account, wasmPath] = process.argv.slice(2);
if (!account || !wasmPath) { console.error('usage: node deploy.cjs <account> <wasm>'); process.exit(1); }

(async () => {
  const wasm = fs.readFileSync(wasmPath);
  const localHash = crypto.createHash('sha256').update(wasm).digest('hex');
  console.log(`deploying ${wasmPath} (${wasm.length} bytes) to ${account}`);
  console.log(`local sha256: ${localHash.slice(0, 16)}...`);

  const cred = JSON.parse(fs.readFileSync(`${process.env.HOME}/.near-credentials/testnet/${account}.json`, 'utf8'));
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  await keyStore.setKey('testnet', account, nearAPI.KeyPair.fromString(cred.private_key));
  const near = await nearAPI.connect({ networkId: 'testnet', nodeUrl: 'https://rpc.testnet.fastnear.com', keyStore });
  const acct = await near.account(account);

  const r = await acct.signAndSendTransaction({
    receiverId: account,
    actions: [nearAPI.transactions.deployContract(wasm)],
  });
  const ok = r.status?.SuccessValue !== undefined;
  if (!ok) { console.error('DEPLOY FAILED', JSON.stringify(r.status).slice(0, 200)); process.exit(1); }

  // verify on-chain hash
  const view = await fetch('https://rpc.testnet.fastnear.com', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: '1', method: 'query', params: { request_type: 'view_account', finality: 'final', account_id: account } }),
  }).then(x => x.json());
  const chainHash = Buffer.from(view.result.code_hash, 'base58').toString('hex');
  console.log(`on-chain:     ${chainHash.slice(0, 16)}...`);
  console.log(chainHash === localHash ? '✅ HASH MATCH — deployed the intended wasm' : `❌ MISMATCH (chain ${chainHash} vs local ${localHash})`);
})().catch(e => { console.error('FATAL', (e.message || e).toString().slice(0, 300)); process.exit(1); });
