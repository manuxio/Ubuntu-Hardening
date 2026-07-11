# Host-side Tier-1 runner for Windows PowerShell (mirrors test/run-tests.sh).
# Needs no host bash — bash only runs INSIDE the container. Run from anywhere:
#     powershell -ExecutionPolicy Bypass -File test\run-tests.ps1
#
# Uses Continue (not Stop) + explicit $LASTEXITCODE checks, because redirecting a
# native exe's stderr under -ErrorActionPreference Stop throws in PowerShell 5.1.
$ErrorActionPreference = 'Continue'
Set-Location (Join-Path $PSScriptRoot '..')
$Repo = (Get-Location).Path

$Image   = 'ubuntu-harden-tier1'
$Net     = 'harden-test-net'
$Db      = 'harden-test-db'
$DbImage = 'mariadb:11.4'      # MariaDB = the usual Joomla/WordPress DB
$DbName  = 'joomla_db'
$DbUser  = 'web_user'
$DbPass  = 'web_userpass'
$DbRoot  = 'rootpass'

function Cleanup {
  Write-Host '>> cleanup'
  if (docker ps -aq -f "name=^$Db$")        { docker rm -f $Db | Out-Null }
  if (docker network ls -q -f "name=^$Net$") { docker network rm $Net | Out-Null }
}

$testExit = 1
try {
  Write-Host ">> building $Image"
  docker build -t $Image -f test/Dockerfile.tier1 test/
  if ($LASTEXITCODE -ne 0) { throw 'docker build failed' }

  Write-Host ">> starting ephemeral MariaDB ($DbImage)"
  if (-not (docker network ls -q -f "name=^$Net$")) { docker network create $Net | Out-Null }
  if (docker ps -aq -f "name=^$Db$") { docker rm -f $Db | Out-Null }
  docker run -d --name $Db --network $Net `
    -e "MARIADB_ROOT_PASSWORD=$DbRoot" -e "MARIADB_DATABASE=$DbName" `
    -e "MARIADB_USER=$DbUser" -e "MARIADB_PASSWORD=$DbPass" `
    $DbImage | Out-Null

  Write-Host -NoNewline '>> waiting for MariaDB '
  $ready = $false
  for ($i = 0; $i -lt 60; $i++) {
    docker exec $Db mariadb -uroot -p"$DbRoot" -e 'SELECT 1' 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $ready = $true; Write-Host ' ready'; break }
    Write-Host -NoNewline '.'; Start-Sleep -Seconds 2
  }
  if (-not $ready) { Write-Host ' TIMEOUT'; docker logs --tail 20 $Db }

  Write-Host '>> running ephemeral Tier-1 container'
  docker run --rm --network $Net `
    -e "DB_TEST_HOST=$Db" -e 'DB_TEST_PORT=3306' `
    -e "DB_TEST_USER=$DbUser" -e "DB_TEST_PASS=$DbPass" -e "DB_TEST_NAME=$DbName" `
    -v "${Repo}:/work" -w /work `
    $Image bash /work/test/in-container.sh
  $testExit = $LASTEXITCODE
}
finally {
  Cleanup
}
exit $testExit
