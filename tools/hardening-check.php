<?php
declare(strict_types=1);
/**
 * hardening-check.php — PHP hardening self-test  ·  by manux4CONINET
 * -----------------------------------------------------------------------------
 * TEMPORARY DIAGNOSTIC. Deploy into a site's docroot (via FTP/SFTP), open it in
 * a browser to see the report, or fetch `?format=json` for machine output —
 * then DELETE IT. Leaving it in place discloses your hardening posture.
 *
 * Optional live DB check:  ?db_host=127.0.0.1&db_user=..&db_pass=..&db_name=..
 * Force output:            ?format=json | ?format=html
 * -----------------------------------------------------------------------------
 */

header('X-Robots-Tag: noindex, nofollow', true);
header('Cache-Control: no-store, max-age=0');

/* ------------------------------------------------------------------ helpers */
const S_PASS = 'pass', S_FAIL = 'fail', S_WARN = 'warn', S_INFO = 'info';
$RESULTS = [];
function chk(string $group, string $name, string $status, string $detail = ''): void {
    global $RESULTS;
    $RESULTS[] = ['group' => $group, 'name' => $name, 'status' => $status, 'detail' => $detail];
}
function flag_on(string $k): bool { return filter_var(ini_get($k), FILTER_VALIDATE_BOOLEAN); }
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

$scheme_https = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
    || (($_SERVER['SERVER_PORT'] ?? '') === '443')
    || (strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https');

/* ---------------------------------------------------------------- identity */
$whoami = function_exists('posix_geteuid')
    ? (posix_getpwuid(posix_geteuid())['name'] ?? (string)posix_geteuid())
    : (getenv('USER') ?: '?');
$groups = [];
if (function_exists('posix_getgroups')) {
    foreach (posix_getgroups() as $gid) {
        $g = function_exists('posix_getgrgid') ? posix_getgrgid($gid) : null;
        $groups[] = $g['name'] ?? (string)$gid;
    }
}
chk('Identity', 'Runtime user', S_INFO, $whoami);
chk('Identity', 'Supplementary groups',
    in_array('www-data', $groups, true) ? S_PASS : S_INFO,
    ($groups ? implode(', ', $groups) : 'n/a') . (in_array('www-data', $groups, true) ? '  (in www-data)' : ''));

/* ----------------------------------------------------- dangerous functions */
$dfset = array_filter(array_map('trim', explode(',', (string)ini_get('disable_functions'))));
$dangerous = ['exec','shell_exec','system','passthru','popen','proc_open',
    'pcntl_exec','proc_close','proc_get_status','dl','posix_kill','posix_setuid'];
$enabled = [];
foreach ($dangerous as $f) {
    if (function_exists($f) && !in_array($f, $dfset, true)) { $enabled[] = $f; }
}
chk('Dangerous functions', 'exec-family disabled',
    $enabled ? S_FAIL : S_PASS,
    $enabled ? 'STILL CALLABLE: ' . implode(', ', $enabled) : 'all ' . count($dangerous) . ' blocked');

$execWorks = false;
if (function_exists('exec')) { $o = []; @exec('id', $o); $execWorks = !empty($o); }
chk('Dangerous functions', 'Live exec() blocked',
    $execWorks ? S_FAIL : S_PASS,
    $execWorks ? 'exec() produced output — NOT blocked' : 'exec() unavailable / produced nothing');

/* ------------------------------------------------------------- open_basedir */
$obd = (string)ini_get('open_basedir');
chk('open_basedir', 'Configured', $obd !== '' ? S_PASS : S_FAIL, $obd !== '' ? $obd : 'NOT SET — jail disabled');
chk('open_basedir', 'Read /etc/passwd blocked',
    (@file_get_contents('/etc/passwd') === false) ? S_PASS : S_FAIL,
    (@file_get_contents('/etc/passwd') === false) ? 'blocked' : 'READABLE — jail leak');
chk('open_basedir', 'List / blocked',
    (@scandir('/') === false) ? S_PASS : S_FAIL,
    (@scandir('/') === false) ? 'blocked' : 'listable — jail leak');

/* --------------------------------------------------------- remote wrappers */
chk('Remote wrappers', 'allow_url_fopen off', flag_on('allow_url_fopen') ? S_FAIL : S_PASS, flag_on('allow_url_fopen') ? 'ON — SSRF/RFI risk' : 'off');
chk('Remote wrappers', 'allow_url_include off', flag_on('allow_url_include') ? S_FAIL : S_PASS, flag_on('allow_url_include') ? 'ON — RFI risk' : 'off');
if (!flag_on('allow_url_fopen')) {
    // With fopen wrappers off this fails immediately — no network attempt / no hang.
    chk('Remote wrappers', 'Live http:// fetch blocked',
        (@file_get_contents('http://169.254.169.254/') === false) ? S_PASS : S_FAIL, 'url wrappers disabled');
}

/* ----------------------------------------------------------- info leakage */
chk('Info leakage', 'expose_php off', flag_on('expose_php') ? S_FAIL : S_PASS, flag_on('expose_php') ? 'ON — leaks PHP version' : 'off');
chk('Info leakage', 'display_errors off', flag_on('display_errors') ? S_FAIL : S_PASS, flag_on('display_errors') ? 'ON — leaks paths/errors' : 'off');
chk('Info leakage', 'log_errors on', flag_on('log_errors') ? S_PASS : S_INFO, flag_on('log_errors') ? 'on' : 'off');

/* ------------------------------------------------------- filesystem model */
$codeProbe = __DIR__ . '/.hchk_' . bin2hex(random_bytes(4));
$codeWrite = @file_put_contents($codeProbe, 'x');
if ($codeWrite !== false) { @unlink($codeProbe); }
chk('Filesystem', 'Code dir NOT writable',
    ($codeWrite === false) ? S_PASS : S_FAIL,
    ($codeWrite === false) ? h(__DIR__) . ' is read-only' : 'WRITABLE — a webshell could be dropped here');

$tmpDir = (string)(ini_get('upload_tmp_dir') ?: sys_get_temp_dir());
$tmpProbe = rtrim($tmpDir, '/') . '/.hchk_' . bin2hex(random_bytes(4));
$tmpWrite = @file_put_contents($tmpProbe, 'x');
if ($tmpWrite !== false) { @unlink($tmpProbe); }
chk('Filesystem', 'Writable temp works',
    ($tmpWrite !== false) ? S_PASS : S_WARN, $tmpDir . (($tmpWrite !== false) ? ' (writable)' : ' (NOT writable)'));

/* ---------------------------------------------------------------- session */
foreach (['session.cookie_httponly' => 'cookie_httponly',
          'session.use_strict_mode' => 'use_strict_mode',
          'session.use_only_cookies' => 'use_only_cookies'] as $ini => $label) {
    chk('Session', $label, flag_on($ini) ? S_PASS : S_FAIL, flag_on($ini) ? 'on' : 'off');
}
$samesite = (string)ini_get('session.cookie_samesite');
chk('Session', 'cookie_samesite', $samesite !== '' ? S_PASS : S_WARN, $samesite !== '' ? $samesite : 'not set');
if ($scheme_https) {
    chk('Session', 'cookie_secure (HTTPS)', flag_on('session.cookie_secure') ? S_PASS : S_FAIL, flag_on('session.cookie_secure') ? 'on' : 'off — should be on over HTTPS');
} else {
    chk('Session', 'cookie_secure', flag_on('session.cookie_secure') ? S_INFO : S_WARN, 'HTTP request — enable once TLS is live');
}

/* ------------------------------------------------------------ resource caps */
foreach (['memory_limit','max_execution_time','upload_max_filesize','post_max_size','max_input_time'] as $k) {
    chk('Resource limits', $k, S_INFO, (string)ini_get($k));
}

/* -------------------------------------------------------------- network egress */
if (function_exists('fsockopen')) {
    $errno = 0; $errstr = '';
    $fp = @fsockopen('1.1.1.1', 80, $errno, $errstr, 3);
    if ($fp) { fclose($fp); chk('Network egress', 'Outbound :80 to 1.1.1.1', S_WARN, 'reachable — egress not restricting port 80'); }
    else { chk('Network egress', 'Outbound :80 to 1.1.1.1', S_PASS, 'blocked (' . ($errstr ?: "errno $errno") . ')'); }
}

/* -------------------------------------------------------------- AppArmor */
$aa = @file_get_contents('/proc/self/attr/current');
if ($aa !== false && trim($aa) !== '') {
    chk('AppArmor', 'Worker confinement', (strpos($aa, '//') !== false) ? S_PASS : S_INFO, trim($aa));
} else {
    chk('AppArmor', 'Worker confinement', S_INFO, 'unreadable (expected under open_basedir) — verify: ps axZ | grep php-fpm');
}

/* -------------------------------------------------------------- database */
if (!empty($_GET['db_host']) && function_exists('mysqli_connect')) {
    if (function_exists('mysqli_report')) { mysqli_report(MYSQLI_REPORT_OFF); }
    $c = @mysqli_connect((string)$_GET['db_host'], (string)($_GET['db_user'] ?? ''), (string)($_GET['db_pass'] ?? ''),
        (string)($_GET['db_name'] ?? ''), (int)($_GET['db_port'] ?? 3306));
    if ($c) {
        $ok = @mysqli_query($c, 'SELECT 1');
        $ver = @mysqli_get_server_info($c);
        @mysqli_close($c);
        chk('Database', 'Connect + SELECT 1', $ok ? S_PASS : S_FAIL, $ok ? ('server ' . $ver) : 'connected but query failed');
    } else {
        chk('Database', 'Connect', S_FAIL, 'connection failed (host/creds/egress?)');
    }
}

/* -------------------------------------------------------------- summary */
$counts = [S_PASS => 0, S_FAIL => 0, S_WARN => 0, S_INFO => 0];
foreach ($RESULTS as $r) { $counts[$r['status']]++; }
$verdict = $counts[S_FAIL] > 0 ? 'FAIL' : ($counts[S_WARN] > 0 ? 'REVIEW' : 'HARDENED');

$meta = [
    'tool' => 'hardening-check by manux4CONINET',
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'runtime_user' => $whoami,
    'host' => (string)($_SERVER['HTTP_HOST'] ?? gethostname()),
    'scheme' => $scheme_https ? 'https' : 'http',
    'generated' => date('c'),
];

/* -------------------------------------------------------------- JSON out */
$wantJson = (($_GET['format'] ?? '') === 'json');
if ($wantJson) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['meta' => $meta, 'summary' => ['verdict' => $verdict, 'counts' => $counts], 'checks' => $RESULTS],
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

/* -------------------------------------------------------------- HTML out */
$badge = ['pass' => '#1f8a4c', 'fail' => '#c0392b', 'warn' => '#c07a1a', 'info' => '#5a6472'];
$verdictColor = ['HARDENED' => '#1f8a4c', 'REVIEW' => '#c07a1a', 'FAIL' => '#c0392b'][$verdict];
$grouped = [];
foreach ($RESULTS as $r) { $grouped[$r['group']][] = $r; }
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>PHP Hardening Check · by manux4CONINET</title>
<style>
  :root{--bg:#0f1216;--card:#171b21;--line:#252b34;--txt:#e6e9ee;--dim:#98a1ad;--accent:#4aa3ff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,sans-serif}
  .wrap{max-width:1000px;margin:0 auto;padding:24px 18px 60px}
  header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:8px}
  header .logo{font-size:30px}
  header h1{font-size:22px;margin:0;font-weight:650;letter-spacing:.2px}
  header .by{color:var(--accent);font-weight:600}
  .warnbar{margin:14px 0;padding:12px 14px;border:1px solid #6b2b2b;background:#2a1414;color:#ffb4b4;border-radius:10px;font-size:14px}
  .meta{display:flex;flex-wrap:wrap;gap:8px 20px;color:var(--dim);font-size:13px;margin:10px 0 20px}
  .meta b{color:var(--txt);font-weight:600}
  .hero{display:flex;align-items:center;gap:20px;flex-wrap:wrap;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin-bottom:22px}
  .verdict{font-size:26px;font-weight:800;padding:8px 18px;border-radius:10px;color:#fff}
  .counts{display:flex;gap:16px;flex-wrap:wrap}
  .count{display:flex;flex-direction:column;align-items:center;min-width:64px}
  .count .n{font-size:24px;font-weight:750}
  .count .l{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim)}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(430px,1fr));gap:16px}
  @media(max-width:520px){.grid{grid-template-columns:1fr}}
  .group{background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:hidden}
  .group h2{margin:0;font-size:13px;text-transform:uppercase;letter-spacing:.7px;color:var(--dim);padding:12px 16px;border-bottom:1px solid var(--line)}
  .row{display:flex;align-items:flex-start;gap:12px;padding:11px 16px;border-bottom:1px solid var(--line)}
  .row:last-child{border-bottom:0}
  .row .name{flex:1;min-width:0}
  .row .name .t{font-weight:600}
  .row .name .d{color:var(--dim);font-size:12.5px;word-break:break-word}
  .tag{flex:none;font-size:11px;font-weight:800;letter-spacing:.5px;color:#fff;padding:3px 9px;border-radius:20px;text-transform:uppercase}
  footer{margin-top:26px;color:var(--dim);font-size:13px;display:flex;gap:16px;flex-wrap:wrap;align-items:center}
  footer a{color:var(--accent);text-decoration:none}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo">🛡️</div>
    <h1>PHP Hardening Check</h1>
    <span class="by">by manux4CONINET</span>
  </header>

  <div class="warnbar">⚠️ <b>Diagnostic tool.</b> This page reveals your hardening posture — <b>delete this file right after use.</b></div>

  <div class="meta">
    <span><b>PHP</b> <?= h($meta['php_version']) ?> (<?= h($meta['sapi']) ?>)</span>
    <span><b>User</b> <?= h($meta['runtime_user']) ?></span>
    <span><b>Host</b> <?= h($meta['host']) ?></span>
    <span><b>Scheme</b> <?= h($meta['scheme']) ?></span>
    <span><b>When</b> <?= h($meta['generated']) ?></span>
  </div>

  <div class="hero">
    <div class="verdict" style="background:<?= $verdictColor ?>"><?= h($verdict) ?></div>
    <div class="counts">
      <?php foreach ([S_PASS=>'passed',S_FAIL=>'failed',S_WARN=>'warnings',S_INFO=>'info'] as $s=>$l): ?>
        <div class="count"><span class="n" style="color:<?= $badge[$s] ?>"><?= $counts[$s] ?></span><span class="l"><?= $l ?></span></div>
      <?php endforeach; ?>
    </div>
  </div>

  <div class="grid">
    <?php foreach ($grouped as $group => $rows): ?>
      <section class="group">
        <h2><?= h($group) ?></h2>
        <?php foreach ($rows as $r): ?>
          <div class="row">
            <div class="name">
              <div class="t"><?= h($r['name']) ?></div>
              <?php if ($r['detail'] !== ''): ?><div class="d"><?= h($r['detail']) ?></div><?php endif; ?>
            </div>
            <span class="tag" style="background:<?= $badge[$r['status']] ?>"><?= h($r['status']) ?></span>
          </div>
        <?php endforeach; ?>
      </section>
    <?php endforeach; ?>
  </div>

  <footer>
    <a href="?format=json">View as JSON →</a>
    <span>hardening-check · by manux4CONINET</span>
  </footer>
</div>
</body>
</html>
