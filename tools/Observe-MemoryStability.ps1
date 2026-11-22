$ErrorActionPreference='Stop'
$receipt=Get-Content -LiteralPath 'C:\ProgramData\RansomGuard\installation-receipt.json' -Raw|ConvertFrom-Json
$runtime=[string]$receipt.runtime
$healthPath=Join-Path $runtime 'observer-ready.json'
$out=Join-Path $PSScriptRoot 'MemoryStability-Result.json'
$mutex=New-Object Threading.Mutex($false,'Global\RansomGuardMemoryObservation')
$owned=$false
try{$owned=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$owned=$true}
if(!$owned){$mutex.Dispose();throw 'Memory observation is already running'}
$samples=New-Object Collections.Generic.List[object]
$errors=New-Object Collections.Generic.List[string]
$started=[datetime]::UtcNow
$timer=[Diagnostics.Stopwatch]::StartNew()
$policyNames=@('response-config.json','live-response-profile.json','console-display.json','scope-authorization.json')
function Health {
 for($retry=0;$retry -lt 4;$retry++){
  try{return Get-Content -LiteralPath $healthPath -Raw|ConvertFrom-Json}catch{if($retry -eq 3){throw};Start-Sleep -Milliseconds 100}
 }
}
function PolicyHashes {
 $map=@{}
 foreach($name in $policyNames){$p=Join-Path $runtime $name;if(Test-Path -LiteralPath $p){$map[$name]=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash}}
 return $map
}
$before=$null;$policyBefore=@{};$report=$null
function Save-Report([string]$state){
 $report=[ordered]@{status=$state;started=$started.ToString('o');updated=[datetime]::UtcNow.ToString('o');elapsedSeconds=$timer.Elapsed.TotalSeconds;requestedSeconds=3600;sampleIntervalSeconds=15;testWorkloadStarted=$false;processRestartRequested=$false;settingsChanged=$false;before=$before;policyBefore=$policyBefore;policyAfter=(PolicyHashes);samples=@($samples.ToArray());errors=@($errors.ToArray());limits='Passive one-hour process memory observation. Does not prove absence of all leaks or stability under high load. Working set alone is not a leak indicator.'}
 $tmp=$out+'.tmp'
 [IO.File]::WriteAllText($tmp,($report|ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
 Move-Item -LiteralPath $tmp -Destination $out -Force
}
try {
 if(Test-Path -LiteralPath $out){Copy-Item -LiteralPath $out -Destination ($out+'.'+$started.ToString('yyyyMMdd-HHmmss')+'.bak')}
 $before=Health;$policyBefore=PolicyHashes
 if($before.worker_state -ne 'running' -or $before.response_authorized -ne $true -or $before.response_collection_invalid -ne $false){throw 'Healthy authorized response worker required'}
 $collectorId=[int]$before.pid
 $collector=Get-Process -Id $collectorId -ErrorAction Stop
 $collectorStart=$collector.StartTime.ToUniversalTime().ToString('o')
 $expectedPaths=@([string]$receipt.paths.python,[string]$receipt.paths.ui,[string]$receipt.paths.firewall)|Where-Object {$_}
 $lastSave=-60
 Write-Output 'OBSERVING MEMORY: 3600 seconds; no load tests, restarts or protection changes.'
 while($true){
  $h=Health;$now=[datetime]::UtcNow
  $age=([datetimeoffset]$now).ToUnixTimeSeconds()-[double]$h.observed_at
  if($age -lt -2 -or $age -gt 30 -or $h.worker_state -ne 'running' -or [int]$h.pid -ne $collectorId){throw 'Collector health or identity changed'}
  if($h.response_authorized -ne $true -or $h.response_collection_invalid -ne $false){throw 'Response authorization or collection validity changed'}
  $processRows=New-Object Collections.Generic.List[object]
  foreach($p in @(Get-Process -Name 'python','pythonw','ransom0-ui','r0-fw-daemon' -ErrorAction SilentlyContinue)){
   try{
    $path=$p.Path
    if($path -notin $expectedPaths){continue}
    $generation=$p.StartTime.ToUniversalTime().ToString('o')
    if($p.Id -eq $collectorId -and $generation -ne $collectorStart){throw 'Collector process generation changed'}
    $role=if($p.Id -eq $collectorId){'collector'}elseif($path -eq [string]$receipt.paths.ui){'ui'}elseif($path -eq [string]$receipt.paths.firewall){'firewall'}else{'backend'}
    $processRows.Add(@{pid=$p.Id;started=$generation;name=$p.ProcessName;role=$role;path=$path;privateBytes=$p.PrivateMemorySize64;workingSetBytes=$p.WorkingSet64;virtualBytes=$p.VirtualMemorySize64;handles=$p.HandleCount;threads=$p.Threads.Count;cpuSeconds=$p.TotalProcessorTime.TotalSeconds})
   }catch{
    if($p.Id -eq $collectorId){throw}
    $processRows.Add(@{pid=$p.Id;name=$p.ProcessName;sampleError=$_.Exception.Message})
   }finally{$p.Dispose()}
  }
  if(!@($processRows|Where-Object role -eq 'collector').Count){throw 'Collector memory could not be sampled'}
  $samples.Add(@{at=$now.ToString('o');elapsedSeconds=$timer.Elapsed.TotalSeconds;processes=@($processRows.ToArray());worker=$h.worker_state;authorized=$h.response_authorized;invalid=$h.response_collection_invalid;pending=$h.pending_intake;kernelQueue=$h.driver_status.queue_depth;deliveryPressure=$h.delivery_backpressure;counters=$h.counter_totals;driver=$h.driver_status})
  if($h.counter_totals.events_dropped -ne $before.counter_totals.events_dropped -or $h.counter_totals.events_flushed -ne $before.counter_totals.events_flushed){throw 'Loss/flush counter changed; observation stopped for review'}
  if($timer.Elapsed.TotalSeconds-$lastSave -ge 60){Save-Report 'OBSERVING';$lastSave=$timer.Elapsed.TotalSeconds}
  if($timer.Elapsed.TotalSeconds -ge 3600){break}
  Start-Sleep -Seconds 15
 }
 $afterHashes=PolicyHashes
 foreach($key in $policyBefore.Keys){if($policyBefore[$key] -ne $afterHashes[$key]){throw 'Protection policy file changed: '+$key}}
 Save-Report 'COMPLETE_REVIEW_REQUIRED'
 Write-Output 'COMPLETE: MemoryStability-Result.json; memory trends require review.'
}catch{
 $errors.Add($_.Exception.Message)
 Save-Report 'STOPPED'
 Write-Output ('STOPPED: '+$_.Exception.Message)
}finally{
 $timer.Stop()
 if($collector){$collector.Dispose()}
 if($owned){$mutex.ReleaseMutex()}
 $mutex.Dispose()
}
