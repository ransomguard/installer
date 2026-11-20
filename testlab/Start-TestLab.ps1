$ErrorActionPreference='Stop'
if (!( [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Start-TestLab.cmd를 우클릭하여 관리자 권한으로 실행하세요.' -ForegroundColor Yellow
    exit 1
}
$receipt=Get-Content "$env:ProgramData\RansomGuard\installation-receipt.json" -Raw|ConvertFrom-Json
$python=$receipt.paths.python
if (!(Test-Path -LiteralPath $python)) { throw 'Ransom0를 먼저 설치해야 합니다.' }
while ($true) {
    Write-Host ''
    Write-Host 'Ransom0 시험 도구 - 전용 시험 파일을 사용하는 무해한 시험' -ForegroundColor Cyan
    Write-Host '1. 대기 상태 점검 (30초 동안 추가 부하 없이 유실 확인)'
    Write-Host '2. 파일 쓰기 부하 (12,000회)'
    Write-Host '3. 대량 파일 쓰기 부하 (120,000회 / 높은 부하·유실 가능)'
    Write-Host '4. 파일 저장·이름/확장자 변경 (1,000회)'
    Write-Host '5. 프로세스 생성·정상 종료 (50개 순차 실행)'
    Write-Host '6. 복구 시험 준비 (전용 폴더와 시험 문서 12개 생성)'
    Write-Host '7. 스냅샷 파일 복구 및 해시 비교 (복구 범위 설정 필요)'
    Write-Host '8. Track A 자동 대응 (규칙 탐지 → 차단·종료·복구 확인)'
    Write-Host '9. Track B 실제 JEV 판정·대응 (API 키 필요 / 시험 수치 전송)'
    Write-Host '10. 기본 시험 자동 실행 (1 → 2 → 4 → 5번)'
    Write-Host '11. 커널 Rule1001 생성 차단 (무해한 실행 파일 복사본 / JEV 미사용)'
    Write-Host '0. 종료'
    $choice=Read-Host '실행할 번호 입력'
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
    Write-Host '승인된 시험 VM에서만 실행하세요. 기존 카운터와 실패 기록은 보존됩니다.' -ForegroundColor Yellow
    if ($choice -in @('7','8','9')) {
        Write-Host '6번으로 준비한 C:\ProgramData\Ransom0TestLab\Protected 폴더를 Ransom0의 복구 범위로 먼저 설정하세요.'
        Write-Host '8·9번은 VM 전체 네트워크를 격리할 수 있습니다. 검토가 필요한 격리는 도구가 임의로 해제하지 않습니다.'
    }
    if ((Read-Host '실행하려면 영문 대문자로 TEST 입력') -cne 'TEST') { continue }
    if ($choice -eq '10') {
        foreach ($profile in @('idle','burst','mixed','process')) {
            & $python "$PSScriptRoot\testlab.py" $profile --confirm-test
            if ($LASTEXITCODE -ne 0) { Write-Host '자동 시험을 중단했습니다. 실패 또는 판단 불가 보고서를 먼저 확인하세요.' -ForegroundColor Yellow; break }
        }
    } else { & $python "$PSScriptRoot\testlab.py" @testArgs --confirm-test }
    Write-Host '결과 저장 위치: C:\ProgramData\Ransom0TestLab\Runs (실행별 report.txt / report.json)'
}
