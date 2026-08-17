const nearAPI = require('/Users/asil/.openclaw/workspace/node_modules/near-api-js');
const fs = require('fs');
const crypto = require('crypto');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const out = [];
(async () => {
  const account = process.argv[2];
  const wasmPath = process.argv[3];
  const wasm = fs.readFileSync(wasmPath);
  const localHash = crypto.createHash('sha256').update(wasm).digest('hex');
  out.push(`local: ${localHash.slice(0,20)} (${wasm.length}B)`);
  const cred = JSON.parse(fs.readFileSync(process.env.HOME + '/.near-credentials/testnet/' + account + '.json', 'utf8'));
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  await keyStore.setKey('testnet', account, nearAPI.KeyPair.fromString(cred.private_key));
  const endpoints = ['https://rpc.testnet.fastnear.com', 'https://rpc.testnet.near.org', 'https://testnet.rpc.pagoda.co'];
  let done = false, lastErr = '';
  for (let i = 0; i < 5 && !done; i++) {
    const ep = endpoints[i % endpoints.length];
    try {
      const near = await nearAPI.connect({ networkId: 'testnet', nodeUrl: ep, keyStore });
      const acct = await near.account(account);
      const r = await acct.signAndSendTransaction({ receiverId: account, actions: [nearAPI.transactions.deployContract(new Uint8Array(wasm))] });
      const ok = r.status?.SuccessValue !== undefined;
      out.push(`deploy ${ep}: ${ok ? 'OK' : 'RECEIPT-FAIL ' + JSON.stringify(r.status).slice(0,120)}`);
      done = ok;
    } catch (e) { lastErr = (e.message || '').slice(0, 150); out.push(`attempt ${i} ${ep} FAIL ${lastErr}`); await sleep(5000); }
  }
  if (!done) { out.push('ALL FAILED — ' + lastErr); fs.writeFileSync('/tmp/deploy_result.txt', out.join('\n')); process.exit(1); }
  await sleep(12);
  const view = await (await fetch('https://rpc.testnet.fastnear.com', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: '1', method: 'query', params: { request_type: 'view_account', finality: 'final', account_id: account } }) })).json();
  const bs58 = require('/Users/asil/.openclaw/workspace/node_modules/bs58');
const chainHash = Buffer.from(bs58.decode(view.result.code_hash)).toString('hex');
  out.push(`chain: ${chainHash.slice(0,20)} ${chainHash === localHash ? 'MATCH ✅' : 'MISMATCH ❌'}`);
  fs.writeFileSync('/tmp/deploy_result.txt', out.join('\n'));
})().catch(e => { fs.writeFileSync('/tmp/deploy_result.txt', 'FATAL ' + (e.message || '').slice(0, 200)); process.exit(1); });
