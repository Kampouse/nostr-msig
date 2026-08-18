// deploy-bench.cjs — deploy wasm + init(new(owner_npubs)) on the bench account
// usage: node deploy-bench.cjs <account> <wasm-path> <owner-npub-hex>
const fs = require('fs');
const crypto = require('crypto');
const nearAPI = require('near-api-js');
const { connect, viewContract, yocto, sleep } = require('./lib.cjs');

const [ACCOUNT, WASM, OWNER_NPUB] = process.argv.slice(2);
if (!ACCOUNT || !WASM || !OWNER_NPUB) {
  console.error('usage: node deploy-bench.cjs <account> <wasm-path> <owner-npub-hex>');
  process.exit(1);
}

(async () => {
  const wasm = fs.readFileSync(WASM);
  const localHash = crypto.createHash('sha256').update(wasm).digest('hex');
  console.log(`wasm: ${WASM} (${wasm.length} bytes) sha256 ${localHash.slice(0, 16)}…`);

  const near = await connect(ACCOUNT);
  const acct = await near.account(ACCOUNT);

  // 1. deploy (with endpoint retry via reconnect)
  let deployed = false, lastErr = '';
  for (let i = 0; i < 4 && !deployed; i++) {
    try {
      const r = await acct.signAndSendTransaction({
        receiverId: ACCOUNT,
        actions: [nearAPI.transactions.deployContract(new Uint8Array(wasm))],
      });
      deployed = r.status?.SuccessValue !== undefined;
      if (!deployed) lastErr = JSON.stringify(r.status).slice(0, 150);
    } catch (e) { lastErr = (e.message || '').slice(0, 150); await sleep(4000); }
  }
  if (!deployed) { console.error(`❌ deploy failed: ${lastErr}`); process.exit(1); }
  console.log(`✅ deployed — tx sent`);

  // 2. verify code hash on chain
  await sleep(2000);
  const { rpcQuery } = require('./lib.cjs');
  const va = await rpcQuery({ request_type: 'view_account', finality: 'final', account_id: ACCOUNT });
  const chainHash = Buffer.from(bs58decode(va.code_hash)).toString('hex');
  if (chainHash !== localHash) { console.error(`❌ hash mismatch chain=${chainHash.slice(0, 16)}`); process.exit(1); }
  console.log(`✅ on-chain code hash matches (${chainHash.slice(0, 16)}…)`);

  // 3. init
  const ir = await acct.functionCall({
    contractId: ACCOUNT,
    methodName: 'new',
    args: { owner_npubs: [OWNER_NPUB] },
    gas: (50n * 10n ** 12n).toString(),
    attachedDeposit: '0',
  });
  if (ir.status?.Failure) { console.error('❌ init failed', JSON.stringify(ir.status.Failure).slice(0, 200)); process.exit(1); }

  // 4. sanity views
  const version = await viewContract(ACCOUNT, 'get_version', {});
  const owners = await viewContract(ACCOUNT, 'get_owners', {}).catch(() => null);
  console.log(`✅ init OK — version ${version}${owners ? `, owners ${JSON.stringify(owners).slice(0, 80)}` : ''}`);
  console.log(`CONTRACT=${ACCOUNT}`);
})().catch((e) => { console.error('FATAL', (e.message || e).toString().slice(0, 300)); process.exit(1); });

function bs58decode(s) {
  // minimal bs58 decode using the bs58 package (sync API in v4)
  return require('bs58').decode(s);
}
