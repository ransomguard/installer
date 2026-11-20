$ErrorActionPreference='Stop'
if (!( [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Right-click Start-TestLab.cmd and choose Run as administrator.' -ForegroundColor Yellow
    exit 1
}
$receipt=Get-Content "$env:ProgramData\RansomGuard\installation-receipt.json" -Raw|ConvertFrom-Json
$python=$receipt.paths.python
if (!(Test-Path -LiteralPath $python)) { throw 'Ransom0 must be installed first.' }
while ($true) {
    Write-Host ''
    Write-Host 'Ransom0 TestLab - bounded harmless tests' -ForegroundColor Cyan
    Write-Host '1. Idle (30 seconds)'
    Write-Host '2. Burst (12,000 writes)'
    Write-Host '3. Burst (120,000 writes - heavy)'
    Write-Host '4. Mixed save + rename (1,000 operations)'
    Write-Host '5. Process creation (50 processes, sequential)'
    Write-Host '6. Prepare disposable recovery documents'
    Write-Host '7. Real VSS recovery + SHA256 verification'
    Write-Host '8. Track A real automatic response (requires configured test scope)'
    Write-Host '9. Track B real JEV response (requires key; sends test metrics)'
    Write-Host '10. Automatic basic suite (idle + 12k burst + mixed + process)'
    Write-Host '11. Kernel child-create blocking rule (harmless WHERE copy; no JEV)'
    Write-Host '0. Exit'
    $choice=Read-Host 'Select'
    if ($choice -eq '0') { break }
    # Windows PowerShell unwraps one switch result to a scalar string.
    # Keep a string array so native-command splatting preserves the whole profile.
    [string[]]$testArgs=@(switch ($choice) {
        '1' { @('idle') }; '2' { @('burst','--count','12000') }
        '3' { @('burst','--count','120000') }; '4' { @('mixed') }
        '5' { @('process') }; '6' { @('prepare') }; '7' { @('recovery') }
        '8' { @('track-a') }; '9' { @('track-b','--allow-jev') }; '10' { @('suite') }; '11' { @('kernel-block') }
        default { @() }
    })
    if (!$testArgs.Count) { continue }
    Write-Host 'Only use in an approved test VM. Counters and failure evidence are preserved.' -ForegroundColor Yellow
    if ($choice -in @('7','8','9')) {
        Write-Host 'Only ProgramData\Ransom0TestLab\Protected is allowed. Set this folder in Ransom0 first.'
        Write-Host 'A/B may isolate the whole VM. Review-required holds are NOT cleared by this tool.'
    }
    if ((Read-Host 'Type TEST to run') -cne 'TEST') { continue }
    if ($choice -eq '10') {
        foreach ($profile in @('idle','burst','mixed','process')) {
            & $python "$PSScriptRoot\testlab.py" $profile --confirm-test
            if ($LASTEXITCODE -ne 0) { Write-Host 'Suite stopped: review the failed/inconclusive report first.' -ForegroundColor Yellow; break }
        }
    } else { & $python "$PSScriptRoot\testlab.py" @testArgs --confirm-test }
    Write-Host 'Report location: C:\ProgramData\Ransom0TestLab\Runs (report.txt / report.json)'
}
