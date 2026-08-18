// run.js — one-shot testbench: create account → deploy → init → verify
//
// Quick start (defaults do everything):
//   cd testbench && npm install && node run.js
//
// Common overrides:
//   BENCH_SIGNER=vault.kampy.testnet   account that funds the bench subaccount
//   BENCH_FUND=8                       NEAR sent to the bench account
//   BENCH_NAME=bench1                  subaccount name (becomes bench1.<signer>)
//   BENCH_OWNER_NSEC=nsec1…            use your real nostr key as owner
//   BENCH_OWNER_SECRET=<64-hex>        …or a raw hex secret
//   SKIP_BUILD=1 BENCH_WASM=path       reuse a wasm instead of building
//   KEEP=1                            don't delete the bench account afterwards (default: keep)
const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SIGNER = process.env.BENCH_SIGNER || 'vault.kampy.testnet';
const NAME = process.env.BENCH_NAME || 'bench' + (Date.now() % 1e6).toString(36);
const ACCOUNT = `${NAME}.${SIGNER}`;
const FUND = process.env.BENCH_FUND || '9';
const WASM_OUT = path.join(ROOT, 'target', 'bench_msig.wasm');

const step = (s) => console.log(`\n━━━ ${s} ━━━`);
const die = (m) => { console.error(`\n❌ ${m}`); process.exit(1); };

function run(cmd, args, env = {}) {
  const r = spawnSync(cmd, args, { stdio: 'inherit', env: { ...process.env, ...env }, cwd: __dirname });
  if (r.status !== 0) die(`step failed: ${cmd} ${args.join(' ')}`);
}

(async () => {
  console.log(`nostr-msig v4 testbench`);
  console.log(`bench account: ${ACCOUNT} (funded ${FUND} Ⓝ from ${SIGNER})`);

  // 1. wasm
  let wasm = process.env.BENCH_WASM;
  if (!process.env.SKIP_BUILD) {
    step('building wasm (rust 1.95 + wasm-opt)');
    run('bash', ['-c', `cd "${ROOT}/contract" && RUSTUP_TOOLCHAIN=1.95.0 cargo build --release --target wasm32-unknown-unknown 2>&1 | tail -2`]);
    run('bash', ['-c', `wasm-opt -Oz --strip-debug --dce "${ROOT}/target/wasm32-unknown-unknown/release/clear_msig.wasm" -o "${WASM_OUT}"`]);
    wasm = WASM_OUT;
  }
  if (!wasm || !fs.existsSync(wasm)) die(`wasm not found (${wasm}) — build or set BENCH_WASM`);
  console.log(`wasm: ${wasm} (${(fs.statSync(wasm).size / 1024).toFixed(0)} KB)`);

  // 2. create + fund
  step(`creating ${ACCOUNT}`);
  run('node', ['create-account.cjs', ACCOUNT]);

  // 3. owner npub
  step('resolving owner key');
  const { sha256 } = require('@noble/hashes/sha256');
  const { bytesToHex } = require('@noble/hashes/utils');
  const { schnorr } = require('@noble/curves/secp256k1');
  const { npubFromHex, nsecToHex } = require('./lib.cjs');
  let ownerHex;
  if (process.env.BENCH_OWNER_SECRET) ownerHex = process.env.BENCH_OWNER_SECRET.replace(/^0x/, '');
  else if (process.env.BENCH_OWNER_NSEC) ownerHex = nsecToHex(process.env.BENCH_OWNER_NSEC);
  else ownerHex = bytesToHex(sha256(new TextEncoder().encode(process.env.BENCH_OWNER_PASSPHRASE || 'nostr-msig-bench-v1')));
  const ownerPubHex = bytesToHex(schnorr.getPublicKey(Buffer.from(ownerHex, 'hex'))); // deploy needs the PUB key
  console.log(`owner npub: ${npubFromHex(ownerPubHex)} (pub ${ownerPubHex.slice(0, 16)}…)`);

  // 4. deploy + init
  step(`deploying to ${ACCOUNT}`);
  run('node', ['deploy-bench.cjs', ACCOUNT, wasm, ownerPubHex]);

  // 5. verify
  step('running full verification bench');
  run('node', ['bench.cjs'], { BENCH_CONTRACT: ACCOUNT, BENCH_RECIPIENT: SIGNER });

  console.log(`\n🎉 TESTBENCH COMPLETE — ${ACCOUNT} is live and fully verified`);
  console.log(`   poke around:  ~/.cargo/bin/near contract call-function as-transaction ${ACCOUNT} get_version json-args {} network-config testnet sign-with-keychain send`);
  console.log(`   tear down:    node cleanup.js ${ACCOUNT} ${SIGNER}`);
})().catch((e) => die(e.message || e));
