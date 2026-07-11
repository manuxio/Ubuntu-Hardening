<?php
declare(strict_types=1);
/**
 * hardening-token.php — keygen + daily token signer for hardening-report.php
 * by manux4CONINET
 * -----------------------------------------------------------------------------
 * Run on a TRUSTED machine (CLI only). The private key must NEVER touch the
 * server — only the public key goes into hardening-report.php (PUBKEY_B64).
 *
 *   php hardening-token.php keygen                 # once: make an Ed25519 keypair
 *   php hardening-token.php sign  <SECRET_B64>     # mint a token valid for today (UTC)
 *   php hardening-token.php sign  <SECRET_B64> 2026-07-12   # for a specific UTC day
 *   SECRET=<b64> php hardening-token.php sign      # secret from the environment
 * -----------------------------------------------------------------------------
 */
if (PHP_SAPI !== 'cli') { http_response_code(403); exit("CLI only\n"); }
if (!function_exists('sodium_crypto_sign_keypair')) { fwrite(STDERR, "libsodium (ext-sodium) required\n"); exit(1); }

const TOKEN_LABEL = 'hardening-check';

/** base64url without padding — URL-safe, matches what hardening-report.php accepts. */
function b64u(string $bin): string { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }

$cmd = $argv[1] ?? '';

if ($cmd === 'keygen') {
    $kp  = sodium_crypto_sign_keypair();
    $pub = sodium_crypto_sign_publickey($kp);
    $sec = sodium_crypto_sign_secretkey($kp);
    echo "PUBLIC key  (paste into hardening-report.php  ->  const PUBKEY_B64):\n";
    echo "  " . base64_encode($pub) . "\n\n";
    echo "SECRET key  (keep PRIVATE — never on the server; use it to sign tokens):\n";
    echo "  " . base64_encode($sec) . "\n";
    exit(0);
}

if ($cmd === 'sign') {
    $secretB64 = $argv[2] ?? (getenv('SECRET') ?: '');
    $sk = base64_decode($secretB64, true);
    if ($sk === false || strlen($sk) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
        fwrite(STDERR, "bad SECRET key (expected base64 of a " . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . "-byte Ed25519 secret)\n");
        exit(1);
    }
    $day = $argv[3] ?? gmdate('Y-m-d');
    $msg = TOKEN_LABEL . '+' . $day;
    $tok = b64u(sodium_crypto_sign_detached($msg, $sk));
    echo "day:   $day (UTC)\n";
    echo "token: $tok\n";
    echo "url:   .../hardening-report.php?key=$tok\n";
    exit(0);
}

fwrite(STDERR, "usage:\n  php hardening-token.php keygen\n  php hardening-token.php sign <SECRET_B64> [YYYY-MM-DD]\n");
exit(1);
