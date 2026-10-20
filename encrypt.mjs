// Encrypts ../AvoKind Dashboard.html into index.html (login page + AES-256-GCM payload).
//
//   node encrypt.mjs --set-password   save/replace the password in the macOS Keychain (asked by macOS, never echoed)
//   node encrypt.mjs                  build index.html using the Keychain password
//
// The password never touches this repo. crypto.json (salt + iterations) is not secret and is
// committed so that "remember me" keeps working across weekly rebuilds with the same password.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { webcrypto as crypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = path.join(here, '..', 'AvoKind Dashboard.html');
const TEMPLATE = path.join(here, 'login.html');
const OUT = path.join(here, 'index.html');
const CONF = path.join(here, 'crypto.json');
const KC = ['-a', 'avokind-dashboard', '-s', 'avokind-dashboard-password'];
const ITER = 600000;

const b64 = u => Buffer.from(u).toString('base64');

if (process.argv.includes('--set-password')) {
  console.log('macOS will ask for the dashboard password twice (min. 12 characters; nothing is shown while typing).');
  execFileSync('security', ['add-generic-password', '-U', ...KC, '-w'], { stdio: 'inherit' });
  console.log('Saved in the Keychain as "avokind-dashboard-password". Now run: node encrypt.mjs');
  process.exit(0);
}

let password = process.env.AVOKIND_TEST_PASSWORD; // only for local tests, never for the published build
if (!password) {
  try { password = execFileSync('security', ['find-generic-password', ...KC, '-w'], { encoding: 'utf8' }).trim(); }
  catch { console.error('No password in the Keychain yet. Run: node encrypt.mjs --set-password'); process.exit(1); }
}
if (password.length < 12) { console.error('Password must be at least 12 characters.'); process.exit(1); }

const conf = existsSync(CONF) ? JSON.parse(readFileSync(CONF, 'utf8'))
  : { salt: b64(crypto.getRandomValues(new Uint8Array(16))), iter: ITER };
if (!existsSync(CONF) && !process.env.AVOKIND_TEST_PASSWORD) writeFileSync(CONF, JSON.stringify(conf, null, 2) + '\n');

const html = readFileSync(SOURCE, 'utf8');
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
const raw = new Uint8Array(await crypto.subtle.deriveBits(
  { name: 'PBKDF2', hash: 'SHA-256', salt: Buffer.from(conf.salt, 'base64'), iterations: conf.iter }, base, 256));
const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
const iv = crypto.getRandomValues(new Uint8Array(12)); // fresh every build
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(html)));

// round-trip check before writing anything
const back = new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
if (back !== html) { console.error('Round-trip check failed; nothing written.'); process.exit(1); }

const payload = JSON.stringify({ v: 1, salt: conf.salt, iter: conf.iter, iv: b64(iv), ct: b64(ct) });
const page = readFileSync(TEMPLATE, 'utf8').replace('__PAYLOAD__', payload);

// never publish plaintext data by accident
for (const leak of ['DEFAULT_DATA', 'Marketing Spend', 'Revenue ($)', 'const PAID']) {
  if (page.includes(leak)) { console.error('Plaintext found in output (' + leak + '); nothing written.'); process.exit(1); }
}
const out = process.env.AVOKIND_TEST_OUT || OUT;
writeFileSync(out, page);
console.log('Wrote ' + path.basename(out) + ' (' + Math.round(page.length / 1024) + ' KB, encrypted).');
