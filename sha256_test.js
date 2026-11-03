const crypto = require('crypto');

// --- SHA-256 на чистом JS (константы вычисляются по определению FIPS 180-4) ---
function firstPrimes(n) {
  const ps = [];
  let x = 2;
  while (ps.length < n) {
    let p = true;
    for (const q of ps) { if (q * q > x) break; if (x % q === 0) { p = false; break; } }
    if (p) ps.push(x);
    x++;
  }
  return ps;
}
const PR = firstPrimes(64);
const TWO32 = 4294967296;
// дробная часть корня * 2^32 — корректность проверяется тестами ниже
function frac32(v) { return (v - Math.floor(v)) * TWO32; }
const H0 = PR.slice(0, 8).map(p => (frac32(Math.sqrt(p))) | 0);
const KC = PR.map(p => (frac32(Math.pow(p, 1 / 3))) | 0);

function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

function sha256hex(str) { // str: latin1-строка (все коды < 256)
  let H = H0.slice();
  const W = new Int32Array(64);
  let msg = str + '\x80';
  while (msg.length % 64 !== 56) msg += '\x00';
  const bitLen = str.length * 8;
  const hi = Math.floor(bitLen / TWO32), lo = (bitLen >>> 0);
  msg += String.fromCharCode(
    (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
    (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff
  );
  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      W[i] = ((msg.charCodeAt(off + i * 4) & 0xff) << 24) |
             ((msg.charCodeAt(off + i * 4 + 1) & 0xff) << 16) |
             ((msg.charCodeAt(off + i * 4 + 2) & 0xff) << 8) |
             (msg.charCodeAt(off + i * 4 + 3) & 0xff);
    }
    for (let i = 16; i < 64; i++) {
      const x = W[i - 15], y = W[i - 2];
      const s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
      const s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + KC[i] + W[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  let out = '';
  for (const v of H) out += ('00000000' + (v >>> 0).toString(16)).slice(-8);
  return out;
}

// --- тесты: сравнение с node crypto на случайных данных ---
let ok = true;
const cases = ['', 'abc', 'x', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(63), 'a'.repeat(64),
  'a'.repeat(1000), '0123456789 \x01\x02\x7f', 'Héllo wörld'];
for (let i = 0; i < 200; i++) {
  const bytes = crypto.randomBytes(Math.floor(Math.random() * 300));
  cases.push(bytes.toString('latin1'));
}
for (const s of cases) {
  const mine = sha256hex(s);
  const ref = crypto.createHash('sha256').update(Buffer.from(s, 'latin1')).digest('hex');
  if (mine !== ref) { ok = false; console.log('FAIL', JSON.stringify(s.slice(0, 20)), '\n ref', ref, '\n got', mine); }
}
console.log(ok ? 'SHA256 OK (' + cases.length + ' векторов)' : 'SHA256 FAILED');
