# Run from the trusted installation before publishing the storage-owner marker.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Bundle, [Parameter(Mandatory)][string]$VolumeRoot)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required.' }
$service = 'Ransom0Vss'
$storageSid = 'S-1-5-80-3755250574-3201999084-3738073789-2921536738-940384076'
$programs = [Environment]::GetFolderPath('ProgramFiles').TrimEnd('\')
$package = (Get-Item -LiteralPath $Bundle).FullName
if (-not $package.StartsWith($programs+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Expected Program Files bundle.' }
if ($VolumeRoot -notmatch '^[A-Za-z]:\\$') { throw 'Expected a local drive root.' }
$volumes = @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' | Where-Object DriveLetter -eq $VolumeRoot.Substring(0,2))
if ($volumes.Count -ne 1 -or $volumes[0].DeviceID -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$') { throw 'Approved fixed volume unavailable.' }
$approvedVolume = [string]$volumes[0].DeviceID
$python = Join-Path $package 'python\python.exe'
$backend = Join-Path $package 'backend'
$binPath = '"' + $python + '" -I -B -m ransomguard.vss_broker'
$trusted = @('S-1-5-18','S-1-5-32-544',$identity.User.Value,
             'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
function Assert-TrustedFileSystemNode($Item) {
    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point in code path: $($Item.FullName)" }
    $acl = Get-Acl -LiteralPath $Item.FullName
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw "Unexpected code owner: $($Item.FullName)"
    }
    $mask = 0x500D0156
    foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne 'Allow' -or ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if ($ace.IdentityReference.Value -notin $trusted -and ([long]$ace.FileSystemRights -band $mask)) {
            throw "Code writable by another principal: $($Item.FullName)"
        }
    }
}
$ancestor = Get-Item -LiteralPath $package
while ($ancestor) {
    Assert-TrustedFileSystemNode $ancestor
    if ($ancestor.FullName -eq $programs) { break }
    $ancestor = $ancestor.Parent
}
$pending = [Collections.Generic.Stack[IO.FileSystemInfo]]::new()
$codeTrees = @((Split-Path -Parent $python), $backend)
$setup = Join-Path $package 'setup'
if (Test-Path -LiteralPath $setup -PathType Container) { $codeTrees += $setup }
foreach ($tree in $codeTrees) { $pending.Push((Get-Item -LiteralPath $tree)) }
while ($pending.Count) {
    $item = $pending.Pop()
    Assert-TrustedFileSystemNode $item
    if ($item.PSIsContainer) {
        foreach ($child in (Get-ChildItem -LiteralPath $item.FullName -Force)) { $pending.Push($child) }
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $backend 'ransomguard\vss_broker.py') -PathType Leaf)) { throw 'VSS provider module missing.' }
$pathFiles = @(Get-ChildItem -LiteralPath (Split-Path -Parent $python) -Filter '*._pth' -File)
if ($pathFiles.Count -ne 1) { throw 'Expected the isolated embedded Python path configuration.' }
foreach ($line in (Get-Content -LiteralPath $pathFiles[0].FullName)) {
    $value = $line.Trim()
    if (-not $value -or $value.StartsWith('#') -or $value -eq 'import site') { continue }
    if ([IO.Path]::IsPathRooted($value) -or $value -match '^import\s') { throw 'Untrusted Python module search path.' }
    $resolved = [IO.Path]::GetFullPath((Join-Path $pathFiles[0].Directory.FullName $value))
    if (-not ($codeTrees | Where-Object { $resolved -eq $_ -or $resolved.StartsWith($_+'\',[StringComparison]::OrdinalIgnoreCase) })) {
        throw 'Python searches outside the inspected code trees.'
    }
}
$keyPath = 'SOFTWARE\Ransom0\VssBroker'
$machine = [Microsoft.Win32.Registry]::LocalMachine
$sddl = "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;$storageSid)"
$controlSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x10;;;$storageSid)"
$sc = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
$existing = Get-CimInstance Win32_Service -Filter "Name='Ransom0Vss'"
$registry = $machine.OpenSubKey($keyPath)
if ($existing -or $registry) {
    if (-not $existing -or -not $registry) { if ($registry) { $registry.Close() }; throw 'Incomplete provider registration requires inspection.' }
    try {
        if ($existing.PathName -ne $binPath -or $existing.StartName -ne 'LocalSystem' -or $existing.StartMode -ne 'Manual' -or
            $registry.GetValue('Volume') -ne $approvedVolume) { throw 'Existing provider settings differ.' }
        $acl = $registry.GetAccessControl()
        if ($acl.GetSecurityDescriptorSddlForm('Access') -ne ([Security.AccessControl.RawSecurityDescriptor]::new($sddl)).GetSddlForm('Access')) {
            throw 'Existing VSS registry permissions differ.'
        }
        foreach ($childName in @('Owned','Requests','Deleted')) {
            $child = $registry.OpenSubKey($childName)
            if (-not $child) { throw 'VSS journal missing.' }
            try {
                $childAcl = $child.GetAccessControl()
                if ($childAcl.AreAccessRulesProtected -or $childAcl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]).Count) {
                    throw 'Unexpected explicit VSS journal permissions.'
                }
            } finally { $child.Close() }
        }
    } finally { $registry.Close() }
} else {
    $acl = [Security.AccessControl.RegistrySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($sddl)
    $registry = $machine.CreateSubKey($keyPath,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,$acl)
    try {
        $registry.SetValue('Volume',$approvedVolume)
        foreach ($childName in @('Owned','Requests','Deleted')) { $registry.CreateSubKey($childName).Close() }
        $registry.Flush()
    } finally { $registry.Close() }
    $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
        Name=$service; DisplayName='Ransom0 VSS Provider'; PathName=$binPath; ServiceType=[byte]16
        ErrorControl=[byte]1; StartMode='Disabled'; DesktopInteract=$false; StartName='LocalSystem'
    }
    if ($result.ReturnValue) { throw "VSS SCM registration failed ($($result.ReturnValue))." }
    & $sc sdset $service $controlSddl | Out-Null
    if ($LASTEXITCODE) { throw 'Could not set VSS service access. Service remains disabled.' }
}
$currentDacl = @(& $sc sdshow $service | Where-Object { $_ -match '^(O:|D:)' })
if ($LASTEXITCODE -or $currentDacl.Count -ne 1) { throw 'Could not verify VSS service access.' }
$observed = [Security.AccessControl.RawSecurityDescriptor]::new($currentDacl[0].Trim())
# SCM maps generic-all to the service-specific mask when persisting its descriptor.
$rights = @{}
foreach ($ace in $observed.DiscretionaryAcl) {
    if ($ace.AceType -ne 'AccessAllowed' -or $rights.ContainsKey($ace.SecurityIdentifier.Value)) { throw 'Unexpected SCM ACE.' }
    $rights[$ace.SecurityIdentifier.Value] = $ace.AccessMask
}
if ($rights.Count -ne 3 -or $rights[$storageSid] -ne 0x10 -or
    $rights['S-1-5-18'] -notin @(0x10000000,0xF01FF) -or $rights['S-1-5-32-544'] -notin @(0x10000000,0xF01FF)) {
    throw 'Unverified VSS service DACL.'
}
if (-not $existing) { Set-Service -Name $service -StartupType Manual }
