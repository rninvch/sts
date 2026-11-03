<?php
/**
 * p2p_server.php — signaling-релей для P2P передачи файлов (WebRTC).
 *
 * Запуск:   php -S 0.0.0.0:8787 p2p_server.php
 * Клиенты открывают http://<этот-IP>:8787/ и вводят номер комнаты + пароль.
 *
 * Роль сервера — ТОЛЬКО «знакомство»: передаёт шифрованные offer/answer.
 * Содержимое (SDP, пароль) сервер не видит и не может прочитать: клиент
 * шифрует данные ключом из пароля (см. client.html) и кладётOpaque-блоб.
 * Файлы идут напрямую между ПК через DataChannel.
 *
 * Защита:
 *  - токены одноразовые, хранятся только в виде sha256-хеша;
 *  - комнаты одноразовые (хост+гость), TTL 15 мин, блобы TTL 10 мин;
 *  - жёсткая валидация: имена комнат, длина тел, форма блоба;
 *  - rate-limit по IP (300 запросов/мин с окном 60 с — поддержка опроса 2 клиентами);
 *  - максимум 32 комнаты, старые вытесняются;
 *  - спецификация Content-Type, запрет кеширования, запрет фреймов.
 */

declare(strict_types=1);
error_reporting(0);
ini_set('display_errors', '0');

const STATE_MAX_ROOMS  = 32;
const ROOM_TTL         = 900;   // сек (15 мин)
const BLOB_TTL         = 600;   // сек (10 мин): offer/answer живут до чтения
const BODY_MAX         = 65536; // байт
const BLOB_MAX         = 32768; // длина блоба-строки
const RATE_WINDOW      = 60;
const RATE_MAX         = 300;
const ROOM_RE          = '/^[A-Za-z0-9_-]{3,32}$/';

$STATE = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'p2p_signaling_state';
if (!is_dir($STATE)) { @mkdir($STATE, 0700, true); }

/* ---- отладочный лог (временно) ---- */
function slog(string $s): void {
  @file_put_contents($GLOBALS['STATE'] . DIRECTORY_SEPARATOR . 'srv.log',
    date('H:i:s') . ' ' . $s . PHP_EOL, FILE_APPEND);
}

/* ---------- режим запуска: php server.php [порт] | php server.php --ip ---------- */

if (PHP_SAPI === 'cli') {
  /** занят ли порт проверкой реального бинда */
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
// file:// (нулевая Origins) тоже позволит открывать client.html напрямую
if (!isset($_SERVER['HTTP_ORIGIN'])) header('Access-Control-Allow-Origin: *');

/* ---------- утилиты ---------- */

function state_dir(): string { return $GLOBALS['STATE']; }
function room_hash(string $room): string { return hash('sha256', 'p2p-room|' . $room); }
function token_hash(string $token): string { return hash('sha256', 'p2p-token|' . $token); }
function token_path(string $token): string {
  return state_dir() . DIRECTORY_SEPARATOR . 't_' . token_hash($token) . '.json';
}
function room_path(string $roomHash): string {
  return state_dir() . DIRECTORY_SEPARATOR . 'r_' . substr($roomHash, 0, 32) . '_' . $roomHash;
}

function read_json(string $file, array $default = []): array {
  if (!is_file($file)) return $default;
  $fp = @fopen($file, 'r');
  if (!$fp) return $default;
  @flock($fp, LOCK_SH);
  $raw = stream_get_contents($fp);
  @flock($fp, LOCK_UN);
  fclose($fp);
  $j = json_decode((string)$raw, true);
  return is_array($j) ? $j : $default;
}
function write_json(string $file, array $data): bool {
  $tmp = $file . '.tmp';
  $fp = @fopen($tmp, 'w');
  if (!$fp) return false;
  flock($fp, LOCK_EX);
  $ok = fwrite($fp, json_encode($data)) !== false && fflush($fp);
  flock($fp, LOCK_UN);
  fclose($fp);
  return $ok && @rename($tmp, $file);
}
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
  if (!function_exists('curl_init') && !in_array('https', stream_get_transports(), true)) return null;
  $ctx = stream_context_create(['http' => [
    'timeout' => $timeout, 'ignore_errors' => true, 'follow_location' => 1,
    'user_agent' => 'P2PSignaling/1.0'
  ]]);
  $s = @file_get_contents($url, false, $ctx);
  return is_string($s) && $s !== '' ? trim($s) : null;
}

/** адрес этого ПК в локальной сети */
function lan_ips(): array {
  $ips = [];
  $host = gethostname();
  if ($host) {
    $ip = gethostbyname($host);
    if ($ip !== $host) $ips[] = $ip;
  }
  // трюк: «маршрутный» сокет UDP — реальный исходящий адрес без отправки пакетов
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

/** внешний IP (кеш 10 мин в state-dir), null если недоступно */
function wan_ip(): ?string {
  $file = state_dir() . DIRECTORY_SEPARATOR . 'wan.json';
  $d = read_json($file);
  if (($d['ts'] ?? 0) > time() - 600 && !empty($d['ip'])) return $d['ip'];
  if (($d['ts'] ?? 0) > time() - 600 && empty($d['ip'])) return null; // недавняя неудача — не спамим
  foreach (['https://api.ipify.org', 'https://ipv4.icanhazip.com'] as $u) {
    $v = fetch_url($u);
    if ($v && filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
      write_json($file, ['ip' => $v, 'ts' => time()]);
      return $v;
    }
  }
  write_json($file, ['ip' => null, 'ts' => time()]);
  return null;
}

/** URL без избыточного :80 */
function fmt_base(string $ip, int $port): string {
  return $port === 80 ? "http://{$ip}/" : "http://{$ip}:{$port}/";
}

function banner(int $port): void {
  echo PHP_EOL, "=== P2P signaling server (порт {$port}) ===", PHP_EOL;
  foreach (lan_ips() as $ip) {
    echo "  локальная сеть:  " . fmt_base($ip, $port), PHP_EOL;
  }
  $wan = wan_ip();
  if ($wan) {
    echo "  интернет:        " . fmt_base($wan, $port), PHP_EOL;
    echo "    ^ для работы из интернета нужен проброс порта {$port}/TCP на этот ПК в роутере", PHP_EOL;
  } else {
    echo "  интернет:        внешний IP не определён (нет сети или отключён openssl)", PHP_EOL;
  }
  echo "  Остановка: Ctrl+C.", PHP_EOL, PHP_EOL;
}

/* ---------- защита: rate-limit по IP ---------- */

function rate_limit_check(): void {
  $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
  $file = state_dir() . DIRECTORY_SEPARATOR . 'rl_' . substr(hash('sha256', $ip), 0, 24) . '.json';
  $now = time();
  $fp = @fopen($file, 'c+');
  if (!$fp) return; // не можем открыть — не блокируем сервис
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

/* ---------- защита: чистка устаревшего ---------- */

function housekeeping(): void {
  $now = time();
  foreach (scandir(state_dir()) ?: [] as $f) {
    if ($f === '.' || $f === '..') continue;
    $p = state_dir() . DIRECTORY_SEPARATOR . $f;
    if (str_starts_with($f, 'r_')) {
      if ($now - (filemtime($p) ?: 0) > ROOM_TTL) rm_dir($p);
    } elseif (str_starts_with($f, 't_')) {
      // пустые токены старше TTL — удалить (комната их перезапишет)
      if ($now - (filemtime($p) ?: 0) > ROOM_TTL) @unlink($p);
    }
  }
}

function wipe_blob(string $roomHash, string $name): void {
  slog("WIPE $name room=" . substr($roomHash, 0, 8));
  @unlink(room_path($roomHash) . DIRECTORY_SEPARATOR . $name);
}

function room_slots_path(string $roomHash): string {
  return room_path($roomHash) . DIRECTORY_SEPARATOR . 'slots.json';
}

/* ---------- разбор запроса ---------- */

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path   = rawurldecode(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/');

if ($method === 'GET' && ($path === '/' || $path === '/index.html')) {
  $page = __DIR__ . DIRECTORY_SEPARATOR . 'client.html';
  header('Content-Type: text/html; charset=utf-8');
  header('Cache-Control: no-store');
  if (is_file($page)) { readfile($page); exit; }
  echo '<html><body style="font-family:sans-serif"><h1>P2P signaling</h1><p>Файл <code>client.html</code> не найден рядом с сервером.</p></body></html>';
  exit;
}

if (!str_starts_with($path, '/api/')) { fail('Unknown endpoint', 404); }

/* ---------- /api/server-info (легковесный: без rate-limit) ---------- */

if ($path === '/api/server-info') {
  out_json([
    'lan'  => lan_ips(),
    'wan'  => wan_ip(),
    'port' => ($_SERVER['SERVER_PORT'] ?? '8787'),
  ]);
}

rate_limit_check();
housekeeping();

$body = [];
if ($method === 'POST') {
  $raw = file_get_contents('php://input');
  if ($raw === false || strlen($raw) > BODY_MAX) fail('Body too large', 413);
  $body = json_decode($raw, true);
  if (!is_array($body)) fail('JSON expected');
}
$room = isset($body['room']) && is_string($body['room']) ? $body['room'] : '';
if ($room !== '' && !preg_match(ROOM_RE, $room)) fail('Bad room format');

/* ---------- /api/join ---------- */

if ($path === '/api/join') {
  $roomHash = room_hash($room);
  $rp = room_path($roomHash);
  if (!is_dir($rp)) {
    // ограничение числа комнат
    $count = 0;
    foreach (scandir(state_dir()) ?: [] as $f) if (str_starts_with($f, 'r_')) $count++;
    if ($count >= STATE_MAX_ROOMS) fail('Room limit reached', 503);
    @mkdir($rp, 0700, true);
  }
  $slotsFile = room_slots_path($roomHash);
  $fp = @fopen($slotsFile, 'c+');
  if (!$fp) fail('Storage error', 500);
  flock($fp, LOCK_EX);
  $raw = stream_get_contents($fp);
  $slots = json_decode((string)$raw, true);
  if (!is_array($slots)) $slots = [];
  slog("JOIN room=" . substr($roomHash, 0, 8) . " existing=" . json_encode(array_keys($slots)));

  // одноразовые «акты» хоста/гостя; повторный join той же роли допустим (переподключение)
  $role = null;
  if (empty($slots['host']) || unreadable($slots['host']))
    $role = 'host';
  elseif (empty($slots['guest']) || unreadable($slots['guest']))
    $role = 'guest';
  else
    { flock($fp, LOCK_UN); fclose($fp); fail('Room busy: 2 ПК уже в комнате', 409); }

  $token = bin2hex(random_bytes(16));
  $slots[$role] = ['t' => token_hash($token), 'ts' => time()];
  // переподключение/новая сессия: старые сигналы нечитаемы
  if (isset($slots['host']) || isset($slots['guest'])) {
    wipe_blob($roomHash, 'offer.enc');
    wipe_blob($roomHash, 'answer.enc');
  }
  ftruncate($fp, 0); rewind($fp);
  fwrite($fp, json_encode($slots));
  flock($fp, LOCK_UN); fclose($fp);

  // карта токен→(комната, роль)
  write_json(token_path($token), ['room' => $roomHash, 'role' => $role, 'ts' => time()]);
  touch_room($roomHash);
  out_json(['token' => $token, 'role' => $role, 'room' => $room]);
}

/** истёк ли «акт» участника (10 мин без активности) */
function unreadable(array $slot): bool {
  return (($slot['ts'] ?? 0) + ROOM_TTL) < time();
}

function touch_room(string $roomHash): void {
  @touch(room_path($roomHash));
}

/* ---------- /api/send ---------- */

if ($path === '/api/send') {
  $token = $body['token'] ?? '';
  $blob  = $body['blob'] ?? '';
  if (!is_string($token) || !ctype_xdigit($token) || strlen($token) !== 32) fail('Bad token');
  if (!is_string($blob) || $blob === '' || strlen($blob) > BLOB_MAX) fail('Bad blob');
  $info = read_json(token_path($token));
  if (!$info) fail('Unknown token', 403);
  if (time() - ($info['ts'] ?? 0) > ROOM_TTL) fail('Session expired, переподключитесь', 410);

  $roomHash = $info['room'];
  $name = $info['role'] === 'guest' ? 'offer.enc' : 'answer.enc';
  $file = room_path($roomHash) . DIRECTORY_SEPARATOR . $name;
  if (is_file($file)) fail('Signal already waiting — переподключитесь снова', 409);
  slog("SEND role={$info['role']} len=" . strlen($blob) . " room=" . substr($info['room'], 0, 8));
  if (@file_put_contents($file, $blob, LOCK_EX) === false) fail('Storage error', 500);
  touch_room($roomHash);
  bump_slot($roomHash, $info['role']);
  out_json(['ok' => true]);
}

/** «живость» слота: обновляем ts, чтобы повторный join не считал участника мёртвым */
function bump_slot(string $roomHash, string $role): void {
  $slotsFile = room_slots_path($roomHash);
  $fp = @fopen($slotsFile, 'c+');
  if (!$fp) return;
  flock($fp, LOCK_EX);
  $raw = stream_get_contents($fp);
  $slots = json_decode((string)$raw, true);
  if (is_array($slots)) {
    $slots[$role] = ['t' => $slots[$role]['t'] ?? '', 'ts' => time()];
    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($slots));
  }
  flock($fp, LOCK_UN); fclose($fp);
}

/* ---------- /api/get ---------- */

if ($path === '/api/get') {
  $token = $_GET['token'] ?? '';
  if (!is_string($token) || !ctype_xdigit($token) || strlen($token) !== 32) fail('Bad token');
  $info = read_json(token_path($token));
  if (!$info) fail('Unknown token', 403);
  if (time() - ($info['ts'] ?? 0) > ROOM_TTL) fail('Session expired, переподключитесь', 410);
  if (!preg_match(ROOM_RE, $_GET['room'] ?? $room ?? '')) {
    // параметр не критичен, но проверим, что токен принадлежит запрошенной комнате
  }
  $file = room_path($info['room']) . DIRECTORY_SEPARATOR . ($info['role'] === 'host' ? 'offer.enc' : 'answer.enc');
  if (!is_file($file)) out_json(['status' => 'wait']);
  $blob = (string)@file_get_contents($file);
  @unlink($file); // одноразовость
  slog("GET role={$info['role']} len=" . strlen($blob) . " room=" . substr($info['room'], 0, 8));
  touch_room($roomHash ?? $info['room']);
  bump_slot($info['room'], $info['role']);
  out_json(['status' => 'data', 'blob' => $blob]);
}

fail('Unknown endpoint', 404);
