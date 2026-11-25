# Register a separate, demand-start pilot only in an installed, signed test build.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Bundle, [Parameter(Mandatory)][string]$OfflineSource)
$ErrorActionPreference = 'Stop'
$pkg = (Get-Item -LiteralPath $Bundle).FullName
$programs = [Environment]::GetFolderPath('ProgramFiles').TrimEnd('\') + '\'
if (-not $pkg.StartsWith($programs, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Install the reviewed pilot bundle under Program Files first.'
}
$current = Get-Item -LiteralPath $pkg
while ($null -ne $current) {
    if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point in bundle path.' }
    $current = $current.Parent
}
$python = Join-Path $pkg 'python\python.exe'
$module = Join-Path $pkg 'backend\ransomguard\storage_service.py'
if (!(Test-Path -LiteralPath $python -PathType Leaf) -or !(Test-Path -LiteralPath $module -PathType Leaf)) {
    throw 'Packaged interpreter or storage service module missing.'
}
$name = 'Ransom0Storage'
$id = 'S-1-5-80-3755250574-3201999084-3738073789-2921536738-940384076'
$state = Join-Path $pkg 'service-state'
$source = (Get-Item -LiteralPath $OfflineSource).FullName
if ($source -eq (Join-Path $env:ProgramData 'RansomGuard')) {
    throw 'Provide a quiescent offline copy, not the live product data directory.'
}
function Assert-PreviousOwnerIdle {
    $readers = @(Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object {
        $_.CommandLine -match '(?i)(?:^|\s)-m\s+ransomguard\s+observe(?:\s|$)'
    })
    $jobs = @(Get-ScheduledTask | Where-Object {
        $_.TaskName -in @('RansomGuard-InteractiveStartup','RansomGuard-PassiveSupervisor','RansomGuard-HourlySnapshot','RansomGuard-SnapshotRetention') -and $_.State -eq 'Running'
    })
    if ($readers.Count -or $jobs.Count) { throw 'The previous owner is active. Service cutover requires a quiescent clone.' }
}
Assert-PreviousOwnerIdle
if ((Test-Path -LiteralPath $state) -or (Get-Service $name -ErrorAction SilentlyContinue)) {
    throw 'Existing service or data directory preserved. Inspect its registration before upgrading.'
}
& $python -I -B -m ransomguard.storage_acl
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the parent of the storage tree.' }
function New-ProtectedDirectory([string]$Path, [string]$Dacl) {
    if (Test-Path -LiteralPath $Path) { throw 'Refusing to adopt an existing directory.' }
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm($Dacl)
    $null = [System.IO.Directory]::CreateDirectory($Path, $security)
    if (-not (Get-Acl -LiteralPath $Path).AreAccessRulesProtected) { throw 'Directory inherited unexpected access rules.' }
}
# Administrators stage an offline copy in incoming. They get read-only access to private
# stores and no DELETE_CHILD right on the parent. Do not grant write access to ordinary users.
New-ProtectedDirectory $state "D:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BA)(A;OICI;0x1200a9;;;$id)"
# The installing administrator owns the fresh directory. Grant itself create-directory only
# while provisioning, then restore the verified root DACL before registering the service.
$rootAcl = Get-Acl -LiteralPath $state
$tempAcl = Get-Acl -LiteralPath $state
$admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admins,'CreateDirectories','Allow')
$tempAcl.AddAccessRule($rule)
Set-Acl -LiteralPath $state -AclObject $tempAcl
try {
    New-ProtectedDirectory (Join-Path $state 'private') "D:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BA)(A;OICI;FA;;;$id)"
    New-ProtectedDirectory (Join-Path $state 'incoming') "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;$id)"
    New-ProtectedDirectory (Join-Path $state 'requests') "D:P(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;BA)(A;OICI;FA;;;$id)"
    New-ProtectedDirectory (Join-Path $state 'answers') "D:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BA)(A;OICI;FA;;;$id)"
} finally {
    Set-Acl -LiteralPath $state -AclObject $rootAcl
}
& $python -I -B -m ransomguard.service_migration --offline-source $source --incoming (Join-Path $state 'incoming')
if ($LASTEXITCODE -ne 0) { throw 'Offline staging failed. No service was registered.' }
$binPath = '"' + $python + '" -I -B -m ransomguard.storage_service'
# PowerShell's legacy native argument handling strips embedded quotes from binPath.
# Use WMI's typed creation API to preserve the exact path, service identity and manual start.
$r = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
    Name=$name; DisplayName='Ransom0 Storage (pilot)'; PathName=$binPath; ServiceType=[byte]16
    ErrorControl=[byte]1; StartMode='Manual'; DesktopInteract=$false; StartName="NT SERVICE\$name"
}
if ($r.ReturnValue -ne 0) { throw "SCM registration failed ($($r.ReturnValue)); staged files were preserved." }
$installed = Get-CimInstance Win32_Service -Filter "Name='Ransom0Storage'"
if ($installed.PathName -ne $binPath -or $installed.StartName -ne "NT SERVICE\$name" -or $installed.State -ne 'Stopped') {
    throw 'Registration did not match the requested isolated, stopped service.'
}
# A previously imported DPAPI blob keeps its contents and existing operator ACL.
# A later import uses the same reader rule in the packaged bridge source.
$keyFolder = Join-Path $env:ProgramData 'RansomGuard\JevBridge'
$keyFile = Join-Path $keyFolder 'api-key.dpapi'
if (Test-Path -LiteralPath $keyFile -PathType Leaf) {
    foreach ($path in @((Split-Path -Parent $keyFolder), $keyFolder, $keyFile)) {
        if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Unexpected reparse point in the JEV key path. Service remains stopped.'
        }
    }
    $reader = New-Object System.Security.Principal.SecurityIdentifier($id)
    foreach ($path in @($keyFolder, $keyFile)) {
        $acl = Get-Acl -LiteralPath $path
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($reader,'ReadAndExecute','Allow'))
        Set-Acl -LiteralPath $path -AclObject $acl
    }
}
Assert-PreviousOwnerIdle
# Only the final atomic marker changes the launcher and scheduler routing.
$approved = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $state 'incoming\Runtime\protection.json') | ConvertFrom-Json
if ($approved.acknowledged_folder_revert -ne $true) { throw 'Recovery scope approval missing.' }
& (Join-Path $PSScriptRoot 'Register-VssProvider.ps1') -Bundle $pkg -VolumeRoot $approved.volume_root
$marker = Join-Path $state 'incoming\service-owner.json'
[IO.File]::WriteAllText("$marker.new", '{"owner":"Ransom0Storage","schema":1}')
[IO.File]::Move("$marker.new", $marker)
