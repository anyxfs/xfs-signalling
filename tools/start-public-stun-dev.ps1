param(
    [string]$Listen = '127.0.0.1:8787',
    [string]$ServerBinary = (Join-Path $PSScriptRoot '../bin/xfs-signalling.exe')
)
$ErrorActionPreference = 'Stop'
$config = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '../config/public-stun.dev.json') | ConvertFrom-Json
if (-not (Test-Path -LiteralPath $ServerBinary -PathType Leaf)) {
    throw 'Build the server first: go build -o bin/xfs-signalling.exe ./cmd/xfs-signalling'
}
& $ServerBinary -listen $Listen -stun ($config.stun -join ',')
exit $LASTEXITCODE
