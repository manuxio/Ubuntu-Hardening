<?php
// Machine-readable hardening probe. Served at /probe.php inside the docroot;
// php-behavior.sh curls it and asserts each key=PASS. Deleted after the run.
header('Content-Type: text/plain');
function r($k, $ok) { echo $k . '=' . ($ok ? 'PASS' : 'FAIL') . "\n"; }

// open_basedir must block reading outside the jail.
r('open_basedir_passwd', @file_get_contents('/etc/passwd') === false);

// disable_functions must list the exec family.
$df = (string) ini_get('disable_functions');
r('disable_functions_set', stripos($df, 'exec') !== false);

// A live exec() must produce nothing (blocked).
$out = array();
if (function_exists('exec')) { @exec('id', $out); }
r('exec_blocked', empty($out));

// Writing into the CODE dir (docroot root) must fail (runtime user has r-x only).
$code = __DIR__ . '/_probe_code.txt';
r('code_write_denied', @file_put_contents($code, 'x') === false);
@unlink($code);

// Writing into a runtime-writable dir (images/) must succeed.
$data = __DIR__ . '/images/_probe_data.txt';
$okw = @file_put_contents($data, 'x');
r('data_write_ok', $okw !== false);
@unlink($data);

// Remote wrappers off.
r('allow_url_fopen_off', !ini_get('allow_url_fopen'));
r('expose_php_off',      !ini_get('expose_php'));

// Database connectivity (typical CMS need). Creds come via GET because the pool
// runs with clear_env=yes. Only checked when db_host is supplied.
if (!empty($_GET['db_host'])) {
    $ok = false; $ver = '';
    if (function_exists('mysqli_connect')) {
        mysqli_report(MYSQLI_REPORT_OFF);
        $c = @mysqli_connect($_GET['db_host'], $_GET['db_user'] ?? '', $_GET['db_pass'] ?? '', $_GET['db_name'] ?? '', (int)($_GET['db_port'] ?? 3306));
        if ($c) {
            $res = @mysqli_query($c, 'SELECT 1');
            $ok = ($res !== false);
            $ver = @mysqli_get_server_info($c);
            @mysqli_close($c);
        }
    }
    r('db_connect', $ok);
    echo 'db_server=' . $ver . "\n";
}

// Identity (for php-behavior.sh to assert == runtime user).
$who = '?';
if (function_exists('posix_geteuid')) {
    $pw = posix_getpwuid(posix_geteuid());
    $who = $pw['name'] ?? '?';
}
echo 'whoami=' . $who . "\n";
