param(
    [string]$Pairs = '10,50,100,250,500',
    [int]$Cycles = 10,
    [int]$HoldSeconds = 10
)
$ErrorActionPreference = 'Stop'
# Some managed Windows shells expose Path and PATH as duplicate keys; the
# ProcessStartInfo environment map is case-insensitive, so normalize it first.
[Environment]::SetEnvironmentVariable('PATH', $null, [EnvironmentVariableTarget]::Process)
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$serverExe = Join-Path $root 'bin\xfs-signalling.exe'
$loadExe = Join-Path $root 'bin\xfs-signalling-load.exe'
if (-not (Test-Path -LiteralPath $serverExe) -or -not (Test-Path -LiteralPath $loadExe)) {
    throw 'Build first: go build -o bin/xfs-signalling.exe ./cmd/xfs-signalling; go build -o bin/xfs-signalling-load.exe ./cmd/xfs-signalling-load'
}
$artifactDir = Join-Path $root 'artifacts'
New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csvPath = Join-Path $artifactDir "stress-$stamp.csv"
$serverOut = Join-Path $artifactDir "server-$stamp.out.log"
$serverErr = Join-Path $artifactDir "server-$stamp.err.log"
$serverArgs = @('-listen','127.0.0.1:18787','-create-capacity','1000','-ip-join-capacity','1000','-prefix-join-capacity','1000','-max-connections','4096','-ip-connections','4096','-prefix-connections','4096','-connect-capacity','100000')
$server = Start-Process -FilePath $serverExe -ArgumentList $serverArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr
$samples = [System.Collections.Generic.List[object]]::new()
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$previousCpu = [TimeSpan]::Zero
$previousSeconds = 0.0
try {
    $ready = $false
    for ($i = 0; $i -lt 50; $i++) {
        try { Invoke-RestMethod -Uri 'http://127.0.0.1:18787/healthz' -TimeoutSec 1 | Out-Null; $ready = $true; break }
        catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $ready) { throw 'Signaling server did not become healthy' }
    $arguments = @('-url','ws://127.0.0.1:18787/signal','-pairs',$Pairs,'-cycles',"$Cycles",'-hold',"${HoldSeconds}s")
    $loadError = Join-Path $artifactDir "load-$stamp.err.log"
    $load = Start-Process -FilePath $loadExe -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $csvPath -RedirectStandardError $loadError
    while (-not $load.HasExited) {
        try {
            $proc = Get-Process -Id $server.Id -ErrorAction Stop
            $seconds = $clock.Elapsed.TotalSeconds
            $cpu = $proc.TotalProcessorTime
            $percent = 0.0
            if ($seconds -gt $previousSeconds) { $percent = (($cpu - $previousCpu).TotalSeconds / ($seconds - $previousSeconds) / [Environment]::ProcessorCount) * 100 }
            $samples.Add([pscustomobject]@{ elapsed_s=[math]::Round($seconds,2); cpu_percent=[math]::Round($percent,1); working_set_mb=[math]::Round($proc.WorkingSet64/1MB,1); handles=$proc.Handles; threads=$proc.Threads.Count })
            $previousCpu=$cpu; $previousSeconds=$seconds
        } catch { }
        Start-Sleep -Milliseconds 500
        $load.Refresh()
    }
    $load.WaitForExit()
    $loadExit = 0
    if ($null -ne $load.ExitCode) { $loadExit = [int]$load.ExitCode }
    if ($samples.Count -gt 0) {
        $samples | Export-Csv -NoTypeInformation -Path (Join-Path $artifactDir "process-$stamp.csv")
        $summary = [pscustomobject]@{
            samples=$samples.Count
            peak_cpu_percent=($samples | Measure-Object -Property cpu_percent -Maximum).Maximum
            average_sampled_cpu_percent=[math]::Round(($samples | Measure-Object -Property cpu_percent -Average).Average,1)
            peak_working_set_mb=($samples | Measure-Object -Property working_set_mb -Maximum).Maximum
            peak_handles=($samples | Measure-Object -Property handles -Maximum).Maximum
            peak_threads=($samples | Measure-Object -Property threads -Maximum).Maximum
            result_csv=$csvPath
        }
        $summary | Format-List | Out-String | Write-Output
    }
    Get-Content -LiteralPath $csvPath
    if (Test-Path -LiteralPath $loadError) { Get-Content -LiteralPath $loadError }
    if ($loadExit -ne 0) { throw "Load generator failed with exit code $loadExit" }
} finally {
    if (-not $load -or -not $load.HasExited) { if ($load) { Stop-Process -Id $load.Id -ErrorAction SilentlyContinue } }
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -ErrorAction SilentlyContinue }
}
