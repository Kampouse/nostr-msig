// cleanup.js — delete the bench account, refunding balance to a beneficiary
// usage: node cleanup.js <bench-account> [beneficiary]
const nearAPI = require('near-api-js');
const { connect, accountBalance } = require('./lib.cjs');

const [ACCOUNT, BENEFICIARY] = process.argv.slice(2);
if (!ACCOUNT || !BENEFICIARY) { console.error('usage: node cleanup.js <bench-account> <beneficiary>'); process.exit(1); }

(async () => {
  const bal = await accountBalance(ACCOUNT);
  const near = await connect(ACCOUNT);
  const acct = await near.account(ACCOUNT);
  // revoke any access keys by deleting account (state must be empty enough — contract storage refunds apply)
  const r = await acct.deleteAccount(BENEFICIARY);
  console.log(`🗑️  deleted ${ACCOUNT} (~${(Number(bal) / 1e24).toFixed(2)} Ⓝ refunded to ${BENEFICIARY})`);
  console.log(`   tx: ${r.transaction_outcome?.id || 'n/a'}`);
})().catch((e) => { console.error('FATAL', (e.message || e).toString().slice(0, 300)); process.exit(1); });
