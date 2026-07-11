/*
 * webshells.yar — starter YARA rules for PHP webshells / suspicious code.
 * Scanned by scan-malware.sh with YARA-X (`yr`). This is a small, high-signal
 * baseline — extend it or point scan-malware.sh at your own ruleset with
 * --rules. It flags PATTERNS common to webshells; review every hit (a CMS may
 * legitimately use some of these).
 */

rule php_eval_obfuscated {
  meta:
    description = "eval/assert of decoded or inflated data (classic packed webshell)"
  strings:
    $eval = /\b(eval|assert)\s*\(/ nocase
    $d1 = "base64_decode" nocase
    $d2 = "gzinflate" nocase
    $d3 = "gzuncompress" nocase
    $d4 = "str_rot13" nocase
  condition:
    $eval and any of ($d*)
}

rule php_cmd_from_http_input {
  meta:
    description = "OS command executed from HTTP input (command webshell)"
  strings:
    $x = /\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/ nocase
    $i1 = "$_GET"
    $i2 = "$_POST"
    $i3 = "$_REQUEST"
    $i4 = "php://input"
  condition:
    $x and any of ($i*)
}

rule php_eval_http_input {
  meta:
    description = "eval/assert directly on HTTP input (one-liner shell)"
  strings:
    $a = /\b(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
  condition:
    $a
}

rule php_dynamic_call_from_input {
  meta:
    description = "variable function call over HTTP input, e.g. $_GET['f']()"
  strings:
    $a = /\$_(GET|POST|REQUEST)\s*\[[^\]]{1,40}\]\s*\(/
  condition:
    $a
}

rule php_preg_replace_e {
  meta:
    description = "preg_replace with the /e modifier (code execution)"
  strings:
    $a = /preg_replace\s*\(\s*["'][^"']*\/e["']/ nocase
  condition:
    $a
}

rule php_known_webshell_markers {
  meta:
    description = "strings seen in known PHP webshells (WSO/c99/r57/b374k/FilesMan)"
  strings:
    $a = "FilesMan" nocase
    $b = "b374k" nocase
    $c = "c99shell" nocase
    $d = "r57shell" nocase
    $e = "WSOsetcookie" nocase
    $f = "eval($_POST" nocase
    $g = "assert($_POST" nocase
  condition:
    any of them
}
