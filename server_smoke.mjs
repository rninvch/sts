#!/usr/bin/env node
/* smoke для обмена файлами «как FTP»: node server_smoke.mjs [порт=80] */
// Проверки: страница, server-info, метка, строгие офсеты, кусок на чтение, докачка, лимиты, удаление.
const BASE = 'http://127.0.0.1:' + (process.argv[2] || '80');
const ROOM = 'smokerun-' + Date.now().toString(36);

let ok = 0, bad = 0;
function check(name, cond, extra){
  if (cond){ ok++;  console.log('ok  ' + name); }
  else { bad++; console.log('FAIL ' + name + (extra ? ' — ' + extra : '')); }
}
const j = (r) => r.json();
const enc = (b) => btoa(String.fromCharCode(...b));

async function main(){
  // 1. страница
  const page = await fetch(BASE + '/');
  const html = await page.text();
  check('GET / → 200 & html', page.status === 200 && /<html/i.test(html));

  // 2. server-info
  const info = await fetch(BASE + '/api/server-info').then(j);
  check('server-info', Array.isArray(info.lan) && 'port' in info, JSON.stringify(info).slice(0, 80));

  // 3. метка файла
  const meta = JSON.stringify({ v:1, n:'a'.repeat(32), d:btoa('demo'), t:'t'.repeat(64) });
  let r = await fetch(BASE + '/api/meta?room=' + ROOM, {
    method:'POST', headers:{ 'Content-Type':'application/json' },
    body: JSON.stringify({ room: ROOM, id: 'aaaaaaaaaaaaaaaa', meta })
  });
  check('POST /api/meta → ok', r.status === 200, await r.text());

  // 4. бэд-рум
  r = await fetch(BASE + '/api/meta?room=' + 'x', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ room:'x', id:'aaaaaaaaaaaaaaaa', meta })
  });
  check('bad room → 400', r.status === 400, 'code=' + r.status);

  // 5. бэд-id
  r = await fetch(BASE + '/api/meta?room=' + ROOM, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ room: ROOM, id: 'zz', meta })
  });
  check('bad id → 400', r.status === 400, 'code=' + r.status);

  // 6. кусок 100 байт @0
  const c1 = new Uint8Array(100).map((_, i) => i & 0xff);
  r = await fetch(BASE + '/api/up?room=' + ROOM + '&id=aaaaaaaaaaaaaaaa&off=0',
    { method:'POST', headers:{'Content-Type':'application/octet-stream'}, body: c1 });
  const uh1 = await r.json();
  check('POST /api/up @0 → 100', r.status === 200 && uh1.bytes === 100, JSON.stringify(uh1));

  // 7. кусок @100 (докачка)
  const c2 = new Uint8Array(60).fill(7);
  r = await fetch(BASE + '/api/up?room=' + ROOM + '&id=aaaaaaaaaaaaaaaa&off=100',
    { method:'POST', headers:{'Content-Type':'application/octet-stream'}, body: c2 });
  const uh2 = await r.json();
  check('POST /api/up @100 → 160', r.status === 200 && uh2.bytes === 160, JSON.stringify(uh2));

  // 8. нестрогий офсет → 409
  r = await fetch(BASE + '/api/up?room=' + ROOM + '&id=aaaaaaaaaaaaaaaa&off=99',
    { method:'POST', headers:{'Content-Type':'application/octet-stream'}, body: new Uint8Array(5) });
  check('wrong off → 409', r.status === 409, 'code=' + r.status);

  // 9. чтение куска
  r = await fetch(BASE + '/api/file?room=' + ROOM + '&id=aaaaaaaaaaaaaaaa&off=40&len=70');
  const slice = new Uint8Array(await r.arrayBuffer());
  check('GET /api/file slice ok', r.status === 200 && slice.length === 70
    && slice[0] === 40 && slice[60] === 7 && slice[69] === 7);

  // 10. офсет за конец → 416
  r = await fetch(BASE + '/api/file?room=' + ROOM + '&id=aaaaaaaaaaaaaaaa&off=1000&len=50');
  check('read beyond end → 416', r.status === 416, 'code=' + r.status);

  // 11. len > 1MiB → 400
  r = await fetch(BASE + '/api/file?room=' + ROOM + '&id=aaaaaaaaaaaaaaaa&off=0&len=' + (1048576 + 1));
  check('len > DOWN_MAX → 400', r.status === 400, 'code=' + r.status);

  // 12. size/get box
  r = await fetch(BASE + '/api/size?room=' + ROOM + '&id=aaaaaaaaaaaaaaaa').then(j);
  check('GET /api/size -> 160', r.bytes === 160, JSON.stringify(r));
  r = await fetch(BASE + '/api/box?room=' + ROOM).then(j);
  check('GET /api/box -> 1 файл', r.list.length === 1 && r.list[0].id === 'aaaaaaaaaaaaaaaa', JSON.stringify(r).slice(0,120));

  // 13. сброс меткой: тело снова 0
  r = await fetch(BASE + '/api/meta?room=' + ROOM, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ room: ROOM, id: 'aaaaaaaaaaaaaaaa', meta })
  }).then(j);
  r = await fetch(BASE + '/api/size?room=' + ROOM + '&id=aaaaaaaaaaaaaaaa').then(j);
  check('meta resets body → 0', r.bytes === 0, JSON.stringify(r));

  // 14. удаление
  r = await fetch(BASE + '/api/del?room=' + ROOM, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ room: ROOM, id: 'aaaaaaaaaaaaaaaa' })
  }).then(j);
  r = await fetch(BASE + '/api/size?room=' + ROOM + '&id=aaaaaaaaaaaaaaaa');
  check('DELETE → 404 при size', r.status === 404, 'code=' + r.status);

  console.log(`\n${ok} passed, ${bad} failed`);
  process.exit(bad ? 1 : 0);
}
main();
