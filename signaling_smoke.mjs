// Ручной smoke-тест signaling-сервера: node signaling_smoke.mjs [порт=80]
const BASE = 'http://127.0.0.1:' + (process.argv[2] || '80');
const ROOM = 'smokerun-' + Date.now().toString(36);

const j = async (p, body) => {
  const res = await fetch(BASE + p, body
    ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
    : undefined);
  return { code: res.status, data: await res.json().catch(() => null) };
};

let pass = 0, fail = 0;
const check = (name, cond, extra) => {
  if (cond) { pass++; console.log('ok  ' + name); }
  else { fail++; console.log('FAIL ' + name, extra ?? ''); }
};

// 0. главная страница
{
  const res = await fetch(BASE + '/');
  const html = await res.text();
  check('GET / = 200 & html', res.ok && html.includes('<!DOCTYPE html>') || html.includes('P2P'), res.status);
}

// 1. join двух сторон
const host = await j('/api/join', { room: ROOM });
check('host join', host.code === 200 && host.data.role === 'host' && /^[0-9a-f]{32}$/.test(host.data.token), host.data);
const guest = await j('/api/join', { room: ROOM });
check('guest join', guest.code === 200 && guest.data.role === 'guest', guest.data);

// 2. третьего не пускает
const third = await j('/api/join', { room: ROOM });
check('third join → 409 busy', third.code === 409, third.data);

// 3. гость отправляет offer
const send = await j('/api/send', { token: guest.data.token, blob: 'OFFERBODY-1' });
check('guest send offer', send.code === 200 && send.data.ok === true, send.data);

// 4. повторная отправка → 409
const send2 = await j('/api/send', { token: guest.data.token, blob: 'OFFERBODY-2' });
check('double send → 409', send2.code === 409, send2.data);

// 5. хост получает offer (одноразово)
const g1 = await fetch(BASE + '/api/get?token=' + host.data.token);
const d1 = await g1.json();
check('host get offer', d1.status === 'data' && d1.blob === 'OFFERBODY-1', d1);
const g2 = await j('/api/get?token=' + host.data.token);
check('second get → wait (one-shot)', g2.data.status === 'wait', g2.data);

// 6. хост отправляет answer, гость получает
await j('/api/send', { token: host.data.token, blob: 'ANSWERBODY-1' });
const a1 = await j('/api/get?token=' + guest.data.token);
check('guest get answer', a1.data.status === 'data' && a1.data.blob === 'ANSWERBODY-1', a1.data);

// 7. битый/чужой токен
const badForm = await j('/api/get?token=zzzz');
check('bad token format → 400', badForm.code === 400, badForm.data);
const alien = await j('/api/get?token=' + 'a'.repeat(32));
check('alien token → 403', alien.code === 403, alien.data);

// 8. слишком большой блоб
const big = await j('/api/send', { token: guest.data.token, blob: 'x'.repeat(33000) });
check('huge blob → 400', big.code === 400, big.data);

// 9. кривая комната
const badroom = await j('/api/join', { room: '../hack!' });
check('bad room name', badroom.code === 400, badroom.data);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
