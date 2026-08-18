// create-account.cjs — create + fund a fresh testnet subaccount for the bench
// Uses near-cli-rs for account creation (handles the storage-validation
// ordering that raw near-api-js createAccount trips over).
//
// usage: node create-account.cjs [account]   (must be <name>.<BENCH_SIGNER>)
// env:   BENCH_SIGNER (default vault.kampy.testnet), BENCH_FUND (NEAR, default 8)
//        NEAR_BIN (default ~/.cargo/bin/near)
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const nearAPI = require('near-api-js');
const { accountBalance } = require('./lib.cjs');

const SIGNER = process.env.BENCH_SIGNER || 'vault.kampy.testnet';
const FUND = process.env.BENCH_FUND || '8';
const NEAR_BIN = process.env.NEAR_BIN || process.env.HOME + '/.cargo/bin/near';
const argName = process.argv[2];
const ACCOUNT =
  argName && argName.includes('.') ? argName
  : `${argName || 'bench' + (Date.now() % 1e6).toString(36)}.${SIGNER}`;

const sh = (cmd, args) => new Promise((res) => execFile(cmd, args, { maxBuffer: 12e6 }, (err, stdout, stderr) => res({ err, stdout, stderr })));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  try {
    const bal = await accountBalance(ACCOUNT);
    console.log(`ℹ️  ${ACCOUNT} already exists (${(Number(bal) / 1e24).toFixed(2)} Ⓝ) — reusing`);
    process.exit(0);
  } catch (e) { /* doesn't exist — good */ }

  const signerBal = await accountBalance(SIGNER);
  console.log(`signer ${SIGNER}: ${(Number(signerBal) / 1e24).toFixed(2)} Ⓝ`);
  if (signerBal < BigInt((Number(FUND) + 0.5) * 1e24)) {
    console.error(`❌ signer too low for ${FUND} Ⓝ fund — top it up first`);
    process.exit(1);
  }

  const kp = nearAPI.KeyPair.fromRandom('ed25519');
  const pk = kp.publicKey.toString();

  const args = [
    'account', 'create-account', 'fund-myself', ACCOUNT, `${FUND} NEAR`,
    'use-manually-provided-public-key', pk,
    'sign-as', SIGNER,
    'network-config', 'testnet',
    'sign-with-legacy-keychain', 'send',
  ];
  let txHash = null, lastOut = '';
  for (let attempt = 0; attempt < 3; attempt++) {
    const { err, stdout, stderr } = await sh(NEAR_BIN, args);
    lastOut = (stdout + stderr).replace(/\x1b\[[0-9;]*m/g, '');
    txHash = (lastOut.match(/Transaction ID: ([A-Za-z0-9]+)/) || []).slice(1).find(Boolean);
    // poll for visibility — CLI exit code alone is unreliable on transient RPC hiccups
    for (let i = 0; i < 8; i++) {
      try {
        const bal = await accountBalance(ACCOUNT);
        const outFile = path.join(process.env.HOME, '.near-credentials', 'testnet', `${ACCOUNT}.json`);
        fs.writeFileSync(outFile, JSON.stringify({ account_id: ACCOUNT, private_key: kp.toString() }, null, 2));
        console.log(`✅ created ${ACCOUNT} with ${(Number(bal) / 1e24).toFixed(2)} Ⓝ${txHash ? ` (tx ${txHash})` : ''}`);
        console.log(`   key saved: ${outFile}`);
        console.log(`ACCOUNT=${ACCOUNT}`);
        process.exit(0);
      } catch (e) { await sleep(2500); }
    }
    console.log(`attempt ${attempt + 1}: not visible yet${err ? ` (cli exit err: ${lastOut.slice(-200)})` : ''}`);
    await sleep(2000);
  }
  console.error(`❌ account creation did not land after 3 attempts:\n${lastOut.slice(0, 800)}`);
  process.exit(1);
})().catch((e) => { console.error('FATAL', (e.message || e).toString().slice(0, 300)); process.exit(1); });
