<?php
// Cross-site isolation probe. Deployed into ONE site's docroot and served via
// nginx -> that site's php-fpm pool (so it runs under the site's uid, AppArmor
// hat, open_basedir and egress rules). It then TRIES to break out toward the
// OTHER site and the host. Every "*_denied" key must be PASS. GET params:
//   other=/var/www/html/site2   (the docroot of the OTHER site to attack)
//   db_host,db_user,db_pass,db_name,db_port (own DB — must still work)
header('Content-Type: text/plain');
function r($k, $ok) { echo $k . '=' . ($ok ? 'PASS' : 'FAIL') . "\n"; }

$other = isset($_GET['other']) ? $_GET['other'] : '/var/www/html/site2';

// --- cross-site reads: must be DENIED (open_basedir + AppArmor) --------------
r('xsite_read_config', @file_get_contents($other . '/public_html/configuration.php') === false);
r('xsite_list_dir',    @scandir($other . '/public_html') === false);
r('xsite_read_secret', @file_get_contents($other . '/public_html/SECRET.txt') === false);

// --- cross-site write: must be DENIED ---------------------------------------
r('xsite_write', @file_put_contents($other . '/public_html/images/pwn.txt', 'x') === false);

// --- host secrets: must be DENIED -------------------------------------------
r('read_etc_shadow', @file_get_contents('/etc/shadow') === false);

// --- code execution: must be DENIED (disable_functions + AppArmor no-exec) ---
$out = array();
if (function_exists('exec')) { @exec('id', $out); }
r('exec_denied', empty($out));

$shell = false;
if (function_exists('proc_open')) {
    $desc = array(1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
    $p = @proc_open('/bin/sh -c "echo PWNED"', $desc, $pipes);
    if (is_resource($p)) {
        $o = @stream_get_contents($pipes[1]);
        @proc_close($p);
        $shell = (strpos((string)$o, 'PWNED') !== false);
    }
}
r('shell_spawn_denied', !$shell);

// --- egress: a non-allowed destination must be DENIED (ufw egress by uid) ----
// port 80 to a raw IP is NOT in the allow-list (DNS/DB/mail/443 only).
$e80 = false; $fp = @fsockopen('1.1.1.1', 80, $en, $es, 3);
if ($fp) { $e80 = true; @fclose($fp); }
r('egress_80_denied', !$e80);

// --- own writable dir: must WORK (not over-restricted) -----------------------
$own = __DIR__ . '/images/_own_probe.txt';
$w = @file_put_contents($own, 'ok');
r('own_write_ok', $w !== false);
@unlink($own);

// --- own DB: must WORK (typical CMS need) -----------------------------------
if (!empty($_GET['db_host'])) {
    $ok = false; $ver = '';
    if (function_exists('mysqli_connect')) {
        mysqli_report(MYSQLI_REPORT_OFF);
        $c = @mysqli_connect($_GET['db_host'], $_GET['db_user'] ?? '', $_GET['db_pass'] ?? '',
                             $_GET['db_name'] ?? '', (int)($_GET['db_port'] ?? 3306));
        if ($c) { $ok = (@mysqli_query($c, 'SELECT 1') !== false); $ver = @mysqli_get_server_info($c); @mysqli_close($c); }
    }
    r('own_db_connect', $ok);
    echo 'db_server=' . $ver . "\n";
}

// --- allowed egress (443) should still work (allow-list works both ways) -----
$e443 = false; $fp = @fsockopen('1.1.1.1', 443, $en, $es, 3);
if ($fp) { $e443 = true; @fclose($fp); }
r('egress_443_allowed', $e443);

$who = '?';
if (function_exists('posix_geteuid')) { $pw = posix_getpwuid(posix_geteuid()); $who = $pw['name'] ?? '?'; }
echo 'whoami=' . $who . "\n";
echo 'open_basedir=' . ini_get('open_basedir') . "\n";
