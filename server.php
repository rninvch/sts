<?php
/**
 * server.php — обмен файлами «как FTP» на чистом PHP.
 *
 * Запуск:   php server.php [порт=80]   |   php server.php --ip [порт]
 * Клиенты открывают http://<IP>/ , вводят ОДИНАКОВУЮ комнату и пароль —
 * получают общее «хранилище»: любой загружает файлы, любой скачивает.
 * TCP идёт В СТОРОНУ сервера (исходящие со второго ПК) — работает через
 * любой NAT/CGNAT, протокол — обычный HTTP, WebRTC не нужен вовсе.
 *
 * Защита:
 *  - пароль не отправляется на сервер; файлы шифруются В КЛИЕНТЕ ключом
 *    sha256(комната|пароль); сервер хранит только непрозрачные куски;
 *  - комнаты/ID валидируются, тела ограничены, rate-limit по IP,
 *    TTL хранилища 24 ч, лимиты на размер бокса и их количество.
 *
 * API:
 *  GET  /                    сервис — client.html
 *  GET  /api/server-info     {lan, wan, port}
 *  POST /api/meta            {room,id,meta} — метка файла (+сброс тела)
 *  POST /api/up?room&id&off&tag   raw-тело — кусок шифротекста (строгий порядок)
 *  GET  /api/box?room=       [{id,bytes,meta,ts}]
 *  GET  /api/file?room&id&off&len   raw-тело — кусок шифротекста
 *  GET  /api/size?room&id    {bytes}
 *  POST /api/del             {room,id}
 *  GET  /api/diag            журнал сервера+клиентов (текстовый, для отладки)
 *  POST /api/log             {room,ua,events[]} — журнал, присылаемый клиентом
 */

declare(strict_types=1);
error_reporting(0);
ini_set('display_errors', '0');

const BOX_TTL       = 86400;    // сек неактивности, после которых бокс удаляется
const BOX_MAX       = 2147483648; // 2 GiB на бокс
const BOX_COUNT_MAX = 64;       // максимум боксов
const UP_BODY_MAX   = 655360;   // 640 KiB — один кусок загрузки
const DOWN_MAX      = 1048576;  // 1 MiB — один кусок скачивания
const META_MAX      = 4096;     // шифрованная метка файла
const JSON_MAX      = 8192;
const RATE_WINDOW   = 60;
const RATE_MAX      = 300;
const ROOM_RE       = '/^[A-Za-z0-9_-]{3,32}$/';
const ID_RE         = '/^[0-9a-f]{16}$/';

$STATE = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'p2p_ftp_store';
if (!is_dir($STATE)) { @mkdir($STATE, 0700, true); }

/* ---------- режим запуска ---------- */

if (PHP_SAPI === 'cli') {
  function port_free(int $port): bool {
    $sock = @stream_socket_server('tcp://0.0.0.0:' . $port, $errno, $errstr);
    if ($sock === false) return false;
    fclose($sock);
    return true;
  }
  if (in_array('--ip', $_SERVER['argv'] ?? [], true)) {
    banner((int)($_SERVER['argv'][2] ?? 0) ?: 80);
    exit(0);
  }
  $explicit = isset($_SERVER['argv'][1]) && ($_SERVER['argv'][1] !== '--ip');
  $port = (int)($_SERVER['argv'][1] ?? 0);
  if (!$explicit) {
    $port = 80;
    if (!port_free($port)) {
      $port = 0;
      foreach ([8080, 8081, 8817] as $p) {
        if (port_free($p)) { $port = $p; break; }
      }
      if (!$port) {
        echo "Порт 80 (и запасные 8080/8081/8817) заняты.", PHP_EOL,
             "Запустите с явным портом: php server.php <порт>", PHP_EOL;
        exit(1);
      }
      echo "Порт 80 занят — работаем на {$port}. Адрес будет с портом: http://<IP>:{$port}/", PHP_EOL;
    }
  } elseif (!$port || !port_free($port)) {
    echo !$port ? "Укажите порт: php server.php <порт>" : "Порт {$port} уже занят.", PHP_EOL;
    exit(1);
  }
  banner($port);
  $cmd = escapeshellarg(PHP_BINARY) . ' -S 0.0.0.0:' . $port . ' ' . escapeshellarg(__FILE__);
  passthru($cmd, $code);
  exit((int)$code);
}

/* ---------- ответы ---------- */

function out_json(array $data, int $code = 200): void {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  header('Cache-Control: no-store');
  echo json_encode($data, JSON_UNESCAPED_UNICODE);
  exit;
}
function fail(string $msg, int $code = 400): void {
  out_json(['error' => $msg], $code);
}

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') { http_response_code(204); exit; }

/* ---------- диагностика: журнал каждого запроса (читается через /api/diag) ---------- */

$DIAG = [];

function diag_note(string $key, $val): void { $GLOBALS['DIAG'][$key] = $val; }

register_shutdown_function(function () {
  if (!empty($GLOBALS['DIAG_SKIP'])) return;
  $d = $GLOBALS['DIAG'];
  $room = isset($d['room']) ? substr(hash('sha256', 'p2p-box|' . $d['room']), 0, 8) : '-';
  $id   = isset($d['id']) && is_string($d['id']) ? substr($d['id'] . '......', 0, 6) : '-';
  $q    = '';
  if (isset($d['off'])) $q .= " off={$d['off']}";
  if (isset($d['len'])) $q .= " len={$d['len']}";
  $uri  = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
  $line = implode("\t", [
    date('Y-m-d H:i:s'),
    ($_SERVER['REMOTE_ADDR'] ?? '-'),                       // в /api/diag маскируется
    ($_SERVER['REQUEST_METHOD'] ?? '?') . ' ' . $uri,
    "room={$room} id={$id}{$q}",
    'cl=' . (int)($_SERVER['CONTENT_LENGTH'] ?? 0),
    'recv=' . (isset($d['recv']) ? $d['recv'] : '?'),        // сколько байтов реально дошло
    'ms=' . (int)((microtime(true) - ($_SERVER['REQUEST_TIME_FLOAT'] ?? 0)) * 1000),
    'code=' . http_response_code(),
  ]) . PHP_EOL;
  $file = state_dir() . DIRECTORY_SEPARATOR . 'diag.log';
  @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
  if (@filesize($file) > 200000) {                          // журнал не даём расти бесконечно
    $keep = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    @file_put_contents($file, implode("\n", array_slice($keep, -150)) . "\n", LOCK_EX);
  }
});


/* ---------- утилиты ---------- */

function state_dir(): string { return $GLOBALS['STATE']; }
function room_hash(string $room): string { return hash('sha256', 'p2p-box|' . $room); }
function box_dir(string $roomHash): string {
  return state_dir() . DIRECTORY_SEPARATOR . 'box_' . $roomHash;
}
function body_path(string $dir, string $id): string { return $dir . DIRECTORY_SEPARATOR . $id . '.enc'; }
function meta_path(string $dir, string $id): string { return $dir . DIRECTORY_SEPARATOR . $id . '.meta'; }

function body_size(string $file): int {
  $fp = @fopen($file, 'r');
  if (!$fp) return 0;
  @flock($fp, LOCK_SH);
  fseek($fp, 0, SEEK_END);
  $n = ftell($fp);
  @flock($fp, LOCK_UN);
  fclose($fp);
  return $n ?: 0;
}

function touch_box(string $dir): void { @touch($dir, time()); }

function rm_dir(string $dir): void {
  if (!is_dir($dir)) return;
  foreach (scandir($dir) ?: [] as $f) {
    if ($f === '.' || $f === '..') continue;
    $p = $dir . DIRECTORY_SEPARATOR . $f;
    is_dir($p) ? rm_dir($p) : @unlink($p);
  }
  @rmdir($dir);
}

/* ---------- определение адресов сервера ---------- */

function fetch_url(string $url, int $timeout = 3): ?string {
  $ctx = stream_context_create(['http' => [
    'timeout' => $timeout, 'ignore_errors' => true, 'follow_location' => 1,
    'user_agent' => 'P2PFiles/1.0'
  ]]);
  $s = @file_get_contents($url, false, $ctx);
  return is_string($s) && $s !== '' ? trim($s) : null;
}

function lan_ips(): array {
  $ips = [];
  $host = gethostname();
  if ($host) {
    $ip = gethostbyname($host);
    if ($ip !== $host) $ips[] = $ip;
  }
  $s = @fsockopen('udp://203.0.113.1:9', 9, $en, $es, 1);
  if ($s) {
    $local = stream_socket_get_name($s, false);
    if ($local) $ips[] = preg_replace('/:\d+$/', '', $local);
    fclose($s);
  }
  return array_values(array_unique(array_filter($ips, static fn($ip) =>
    filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
    && !str_starts_with($ip, '127.')
    && !str_starts_with($ip, '169.254.')
  )));
}

function wan_ip(): ?string {
  $file = state_dir() . DIRECTORY_SEPARATOR . 'wan.json';
  $raw = @file_get_contents($file);
  $d = $raw ? json_decode($raw, true) : null;
  if (is_array($d) && ($d['ts'] ?? 0) > time() - 600) return $d['ip'] ?: null;
  foreach (['https://api.ipify.org', 'https://ipv4.icanhazip.com'] as $u) {
    $v = fetch_url($u);
    if ($v && filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
      @file_put_contents($file, json_encode(['ip' => $v, 'ts' => time()]));
      return $v;
    }
  }
  @file_put_contents($file, json_encode(['ip' => null, 'ts' => time()]));
  return null;
}

function fmt_base(string $ip, int $port): string {
  return $port === 80 ? "http://{$ip}/" : "http://{$ip}:{$port}/";
}

function banner(int $port): void {
  echo PHP_EOL, "=== Обмен файлами «как FTP» (порт {$port}) ===", PHP_EOL;
  foreach (lan_ips() as $ip) {
    echo "  локальная сеть:  " . fmt_base($ip, $port), PHP_EOL;
  }
  $wan = wan_ip();
  if ($wan) {
    echo "  интернет:        " . fmt_base($wan, $port), PHP_EOL;
    echo "    ^ нужен проброс порта {$port}/TCP на этот ПК в роутере (или откройте адрес с VPS)", PHP_EOL;
  } else {
    echo "  интернет:        внешний IP не определён", PHP_EOL;
  }
  echo "  Комната+пароль задаются в браузере; файлы шифруются в клиенте,", PHP_EOL,
       "  сервер хранит только непрозрачные куски. Остановка: Ctrl+C.", PHP_EOL, PHP_EOL;
}

/* ---------- защита ---------- */

/* ---------- защита ---------- */

function rate_limit_check(): void {
  $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
  $file = state_dir() . DIRECTORY_SEPARATOR . 'rl_' . substr(hash('sha256', $ip), 0, 24) . '.json';
  $now = time();
  $fp = @fopen($file, 'c+');
  if (!$fp) return;
  flock($fp, LOCK_EX);
  $raw = stream_get_contents($fp);
  $d = json_decode((string)$raw, true);
  if (!is_array($d) || ($d['w'] ?? 0) < $now - RATE_WINDOW) $d = ['w' => $now, 'c' => 0];
  $d['c']++;
  if ($d['c'] > RATE_MAX) {
    flock($fp, LOCK_UN); fclose($fp);
    fail('Rate limit', 429);
  }
  ftruncate($fp, 0); rewind($fp);
  fwrite($fp, json_encode($d));
  flock($fp, LOCK_UN); fclose($fp);
}

function housekeeping(): void {
  $now = time();
  $boxes = [];
  foreach (scandir(state_dir()) ?: [] as $f) {
    if (!str_starts_with($f, 'box_')) continue;
    $p = state_dir() . DIRECTORY_SEPARATOR . $f;
    if ($now - (filemtime($p) ?: 0) > BOX_TTL) { rm_dir($p); continue; }
    $boxes[$f] = filemtime($p) ?: 0;
  }
  while (count($boxes) >= BOX_COUNT_MAX) {           // вытесняем самые старые
    $oldest = array_search(min($boxes), $boxes, true);
    rm_dir(state_dir() . DIRECTORY_SEPARATOR . $oldest);
    unset($boxes[$oldest]);
  }
}


/* ---------- разбор запроса ---------- */

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path   = rawurldecode(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/');

if ($method === 'GET' && ($path === '/' || $path === '/index.html')) {
  $page = __DIR__ . DIRECTORY_SEPARATOR . 'client.html';
  header('Content-Type: text/html; charset=utf-8');
  header('Cache-Control: no-store');
  if (is_file($page)) { readfile($page); exit; }
  echo '<html><body style="font-family:sans-serif"><h1>Обмен файлами</h1><p>Файл <code>client.html</code> не найден рядом с сервером.</p></body></html>';
  exit;
}

if (!str_starts_with($path, '/api/')) { fail('Unknown endpoint', 404); }

if ($path === '/api/server-info') {
  out_json([
    'lan'  => lan_ips(),
    'wan'  => wan_ip(),
    'port' => ($_SERVER['SERVER_PORT'] ?? '80'),
  ]);
}

/* журнал: отдаёт последние 120 записей без IP и без имён комнат (только их хеши) */
if ($path === '/api/diag') {
  $GLOBALS['DIAG_SKIP'] = true;
  $file = state_dir() . DIRECTORY_SEPARATOR . 'diag.log';
  $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
  $lines = array_slice($lines, -120);
  $lines = array_map(static function ($l) {
    $p = explode("\t", $l);
    if (count($p) > 1) $p[1] = '<ip>';
    return implode("\t", $p);
  }, $lines);
  /* строки, присланные самим клиентом */
  $cc = [];
  foreach (scandir(state_dir()) ?: [] as $f) {
    if (!str_starts_with($f, 'clog_')) continue;
    foreach (file(state_dir() . DIRECTORY_SEPARATOR . $f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $l) {
      $cc[] = $f . "\t" . $l;
    }
  }
  usort($cc, static fn($a, $b) => strncmp(substr($a, 5), substr($b, 5), 8) < 0 ? 1 : -1); // блочно; порядок неважен
  $cc = array_slice($cc, -80);
  http_response_code(200);
  header('Content-Type: text/plain; charset=utf-8');
  header('Cache-Control: no-store');
  echo $lines ? implode("\n", $lines) . "\n" : '(журнал сервера пуст)';
  if ($cc) {
    echo "---- журнал клиентов (room=<хеш>) ----\n", implode("\n", $cc);
  }
  exit;
}

/* журнал, который присылает сам клиент */
if ($path === '/api/log' && $method === 'POST') {
  $raw = file_get_contents('php://input');
  diag_note('recv', $raw === false ? 'READ_FAIL' : strlen($raw));
  if ($raw === false) fail('Body expected');
  if (strlen($raw) > 16384) fail('Too many events', 413);
  $j = json_decode($raw, true);
  if (!is_array($j) || !isset($j['events']) || !is_array($j['events'])) fail('Bad log');
  $roomH = (isset($j['room']) && is_string($j['room']) && preg_match(ROOM_RE, $j['room']))
         ? substr(room_hash($j['room']), 0, 8) : 'nolog';
  $ua  = substr(preg_replace('/[^\x20-\x7e]/', '', (string)($j['ua'] ?? '?')), 0, 90);
  $evLine = json_encode($j['events'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  if ($evLine === false) $evLine = '[]';
  $evLine = str_replace(["\r", "\n", "\t"], ' ', $evLine);
  $file = state_dir() . DIRECTORY_SEPARATOR . 'clog_' . $roomH . '.log';
  @file_put_contents($file, date('H:i:s') . "\t{$ua}\t{$evLine}\n", FILE_APPEND | LOCK_EX);
  if (@filesize($file) > 100000) {                    // не даём журнал раздуваться
    $keep = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    @file_put_contents($file, implode("\n", array_slice($keep, -100)) . "\n", LOCK_EX);
  }
  out_json(['ok' => true]);
}

rate_limit_check();
housekeeping();

/** JSON-тело (для POST, кроме /api/up) */
function json_body(): array {
  $raw = file_get_contents('php://input');
  diag_note('recv', $raw === false ? 'READ_FAIL' : strlen($raw));
  if ($raw === false) fail('JSON expected');
  if (strlen($raw) > JSON_MAX) fail('Body too large', 413);
  $body = json_decode($raw, true);
  if (!is_array($body)) fail('JSON expected');
  return $body;
}

/** room из GET или JSON-тела → директория бокса */
function room_box(): string {
  $body = [];
  if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $body = json_body();
  }
  $room = $_GET['room'] ?? ($body['room'] ?? '');
  if (!is_string($room)) diag_note('room', '(не строка)');
  else diag_note('room', $room);
  if (!is_string($room) || !preg_match(ROOM_RE, $room)) fail('Bad room: 3-32 символа, латиница/цифры/-/_');
  $GLOBALS['__jsonBody'] = $body;
  $dir = box_dir(room_hash($room));
  if (!is_dir($dir)) {
    @mkdir($dir, 0700, true);
    touch_box($dir);
  }
  touch_box($dir);
  return $dir;
}

if ($path === '/api/up' && $method === 'POST') {
  /* room в query (raw-тело JSON-парсеру не нужно) */
  $room = $_GET['room'] ?? '';
  diag_note('room', is_string($room) ? $room : '(не строка)');
  if (!is_string($room) || !preg_match(ROOM_RE, $room)) fail('Bad room: 3-32 символа, латиница/цифры/-/_');
  $dir = box_dir(room_hash($room));
  if (!is_dir($dir)) {
    @mkdir($dir, 0700, true);
    touch_box($dir);
  }
} else {
  $dir = room_box();   // валидация room (+JSON-тело при POST)
}


/* ---------- POST /api/meta — метка файла (сброс тела в 0) ---------- */

if ($path === '/api/meta' && $method === 'POST') {
  $body = $GLOBALS['__jsonBody'];
  $id = $body['id'] ?? '';
  $meta = $body['meta'] ?? '';
  diag_note('id', is_string($id) ? $id : '(не строка)');
  diag_note('metaLen', is_string($meta) ? strlen($meta) : -1);
  if (!is_string($id) || !preg_match(ID_RE, $id)) fail('Bad id');
  if (!is_string($meta) || strlen($meta) < 64 || strlen($meta) > META_MAX) fail('Bad meta');
  $bodyFile = body_path($dir, $id);
  $fp = @fopen($bodyFile, 'c+');
  if (!$fp) fail('Storage error', 500);
  flock($fp, LOCK_EX);
  ftruncate($fp, 0); rewind($fp);
  flock($fp, LOCK_UN);
  fclose($fp);
  if (@file_put_contents(meta_path($dir, $id), $meta, LOCK_EX) === false) fail('Storage error', 500);
  out_json(['ok' => true]);
}

/* ---------- POST /api/up — строго последовательное дополнение шифротела ---------- */

if ($path === '/api/up' && $method === 'POST') {
  $id = $_GET['id'] ?? '';
  diag_note('id', is_string($id) ? $id : '(не строка)');
  $off = filter_var($_GET['off'] ?? -1, FILTER_VALIDATE_INT);
  diag_note('off', $off);
  if (!is_string($id) || !preg_match(ID_RE, $id)) fail('Bad id');
  $raw = file_get_contents('php://input');
  diag_note('recv', $raw === false ? 'READ_FAIL' : strlen($raw));
  if ($raw === false) fail('Body expected');
  if (strlen($raw) > UP_BODY_MAX) fail('Body too large', 413);
  if ($off === false || $off < 0) fail('Bad off');
  $part = body_path($dir, $id);
  $cur = body_size($part);
  if ($off !== $cur) fail('Offset mismatch: server=' . $cur, 409);
  if ($cur + strlen($raw) > BOX_MAX) fail('Box full', 507);
  $fp = @fopen($part, 'c+');
  if (!$fp) fail('Storage error', 500);
  flock($fp, LOCK_EX);
  fseek($fp, 0, SEEK_END);
  $ok = fwrite($fp, $raw) === strlen($raw) && fflush($fp);
  flock($fp, LOCK_UN);
  fclose($fp);
  if (!$ok) fail('Storage error', 500);
  out_json(['ok' => true, 'bytes' => $cur + strlen($raw)]);
}

/* ---------- GET /api/box — список файлов бокса ---------- */

if ($path === '/api/box' && $method === 'GET') {
  $list = [];
  foreach (scandir($dir) ?: [] as $f) {
    if (!str_ends_with($f, '.meta')) continue;
    $id = substr($f, 0, -strlen('.meta'));
    if (!preg_match(ID_RE, $id)) continue;
    $meta = @file_get_contents(meta_path($dir, $id));
    if ($meta === false) continue;
    $list[] = [
      'id'    => $id,
      'bytes' => body_size(body_path($dir, $id)),
      'meta'  => $meta,
      'ts'    => filemtime(body_path($dir, $id)) ?: time(),
    ];
  }
  usort($list, static fn($a, $b) => $b['ts'] <=> $a['ts']);
  out_json(['list' => $list]);
}

/* ---------- GET /api/file — кусок шифротела ---------- */

if ($path === '/api/file' && $method === 'GET') {
  $id = $_GET['id'] ?? '';
  $off = filter_var($_GET['off'] ?? -1, FILTER_VALIDATE_INT);
  $len = filter_var($_GET['len'] ?? -1, FILTER_VALIDATE_INT);
  diag_note('id', is_string($id) ? $id : '(не строка)');
  diag_note('off', $off); diag_note('len', $len);
  if (!is_string($id) || !preg_match(ID_RE, $id)) fail('Bad id');
  $off = filter_var($_GET['off'] ?? -1, FILTER_VALIDATE_INT);
  $len = filter_var($_GET['len'] ?? -1, FILTER_VALIDATE_INT);
  if ($off === false || $off < 0 || $len === false || $len <= 0 || $len > DOWN_MAX) fail('Bad off/len');
  $part = body_path($dir, $id);
  $size = body_size($part);
  if ($size === 0 || $off >= $size) fail('Offset beyond end', 416);
  $have = min($len, $size - $off);
  $fp = @fopen($part, 'rb');
  if (!$fp) fail('Storage error', 500);
  flock($fp, LOCK_SH);
  fseek($fp, $off);
  $data = (string)stream_get_contents($fp, $have);
  flock($fp, LOCK_UN);
  fclose($fp);
  header('Content-Type: application/octet-stream');
  header('Content-Length: ' . strlen($data));
  header('X-Bytes-Total: ' . $size);
  echo $data;
  exit;
}

/* ---------- GET /api/size ---------- */

if ($path === '/api/size' && $method === 'GET') {
  $id = $_GET['id'] ?? '';
  diag_note('id', is_string($id) ? $id : '(не строка)');
  if (!is_string($id) || !preg_match(ID_RE, $id)) fail('Bad id');
  if (!is_file(meta_path($dir, $id))) fail('No such file', 404);
  out_json(['bytes' => body_size(body_path($dir, $id))]);
}

/* ---------- POST /api/del ---------- */

if ($path === '/api/del' && $method === 'POST') {
  $body = $GLOBALS['__jsonBody'];
  $id = $body['id'] ?? '';
  if (!is_string($id) || !preg_match(ID_RE, $id)) fail('Bad id');
  @unlink(meta_path($dir, $id));
  @unlink(body_path($dir, $id));
  touch_box($dir);
  out_json(['ok' => true]);
}

fail('Unknown endpoint', 404);
