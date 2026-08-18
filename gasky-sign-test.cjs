const nearAPI = require('/Users/asil/.openclaw/workspace/node_modules/near-api-js');
const fs = require('fs');
const gk = JSON.parse(fs.readFileSync('/tmp/gaskey.json', 'utf8'));
const ACCT = 'msigchk.passkey-wallet-test.testnet';
const rpc = 'https://rpc.testnet.fastnear.com';
const viewKey = async (pub) => {
  const r = await (await fetch(rpc, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ jsonrpc:'2.0', id:'1', method:'query', params:{ request_type:'view_access_key', finality:'final', account_id:ACCT, public_key:pub } }) })).json();
  return r.result;
};
(async () => {
  const before = await viewKey(gk.pub);
  console.log('before:', JSON.stringify(before.permission).slice(0, 160));
  console.log('nonce before:', before.nonce);
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  await keyStore.setKey('testnet', ACCT, nearAPI.KeyPair.fromString(gk.secret));
  const near = await nearAPI.connect({ networkId: 'testnet', nodeUrl: rpc, keyStore });
  const acct = await near.account(ACCT);
  try {
    const r = await acct.functionCall({ contractId: ACCT, methodName: 'nonexistent_probe', args: {}, gas: '30000000000000' });
    console.log('tx status:', JSON.stringify(r.status).slice(0, 120));
  } catch (e) {
    const m = (e.message || '');
    console.log('tx attempted — outcome:', m.includes('FunctionCallError') || m.includes('MethodNotFound') ? 'method missing (EXPECTED — tx was admitted & executed!)' : m.slice(0, 200));
  }
  await new Promise(r => setTimeout(r, 3000));
  const after = await viewKey(gk.pub);
  console.log('after: ', JSON.stringify(after.permission).slice(0, 160));
  console.log('nonce after:', after.nonce);
})().catch(e => console.error('FATAL', (e.message || '').slice(0, 200)));
