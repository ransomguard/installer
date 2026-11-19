"""Fresh-install JEV-only Windows Firewall policy; no policy relaxation on upgrade."""
import ipaddress,json,socket
from pathlib import Path

def configure(bridge,backup,ps,*,resolve_endpoint=True):
    # Resolve before the outbound policy is restricted. The bridge enforces the
    # fixed HTTPS hostname, TLS certificate validation and no redirects/proxy.
    try:
        addresses=sorted({x[4][0] for x in socket.getaddrinfo('api.typesafe.ai',443,type=socket.SOCK_STREAM) if x[0]==socket.AF_INET}) if resolve_endpoint else []
    except socket.gaierror:
        addresses=[]  # A disconnected VM installs with no outbound exception.
    if len(addresses)>8 or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError('Cannot verify public IPv4 addresses for the fixed JEV endpoint')
    data={'bridge':str(bridge),'backup':str(backup),'addresses':addresses}
    result=ps(r'''$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
function Get-EnabledOutboundAllows([switch]$Effective){
 $query=@{Direction='Outbound';Action='Allow';Enabled='True';ErrorAction='Stop'}
 if($Effective){$query.PolicyStore='ActiveStore'}
 try { @(Get-NetFirewallRule @query) }
 catch {
  if($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound,*'){throw}
  # A successfully queried empty result is the desired offline policy.
  @()
 }
}
$existing=Get-NetFirewallRule -Name 'RansomGuard-JEV-Only-HTTPS' -ErrorAction SilentlyContinue
if($existing){throw 'Existing JEV policy requires review; do not overwrite it'}
$export=Join-Path $i.backup 'firewall-before.wfw'
& netsh.exe advfirewall export $export|Out-Null;if($LASTEXITCODE){throw 'Firewall backup failed'}
$hosts=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$old=[IO.File]::ReadAllText($hosts);[IO.File]::WriteAllText((Join-Path $i.backup 'hosts-before.txt'),$old)
if($old -match '(?im)^\s*\S+\s+api\.typesafe\.ai(?:\s|$)'){throw 'Existing JEV hosts mapping requires review'}
$allows=@(Get-EnabledOutboundAllows)
@($allows|Select-Object -ExpandProperty Name)|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $i.backup 'outbound-allows-before.json')
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
# Reuse the queried CIM objects instead of querying each rule again by name.
if($allows.Count -gt 0){Disable-NetFirewallRule -InputObject $allows -ErrorAction Stop|Out-Null}
if(@($i.addresses).Count -gt 0){
 $mapping="`r`n# RansomGuard JEV fixed endpoint`r`n"+((@($i.addresses)|ForEach-Object {$_+' api.typesafe.ai'}) -join "`r`n")+"`r`n"
 [IO.File]::AppendAllText($hosts,$mapping,[Text.Encoding]::ASCII)
 New-NetFirewallRule -Name 'RansomGuard-JEV-Only-HTTPS' -DisplayName 'RansomGuard JEV bridge only (fixed API)' -Direction Outbound -Action Allow -Enabled True -Program $i.bridge -Protocol TCP -RemotePort 443 -RemoteAddress $i.addresses -Profile Any|Out-Null
}
$remaining=@(Get-EnabledOutboundAllows -Effective)
$unexpected=@($remaining|Where-Object {$_.Name -ne 'RansomGuard-JEV-Only-HTTPS'})
if($unexpected.Count -gt 0){throw 'Unexpected effective outbound allow rules remain; containment is not verified'}
if($remaining.Count -ne [int](@($i.addresses).Count -gt 0)){throw 'JEV exception count differs from expected policy'}
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
if($profiles.Count -ne 3 -or @($profiles|Where-Object {$_.Enabled -ne 1 -or $_.DefaultInboundAction -ne 4 -or $_.DefaultOutboundAction -ne 4}).Count -gt 0){throw 'Effective firewall profile verification failed'}
@{configured=$true;verified=$true;disabled_rule_count=$allows.Count;addresses=$i.addresses;jev_exception_ready=(@($i.addresses).Count -gt 0);policy='Block outbound; only resolved JEV bridge HTTPS may be allowed';previous_policy_export=$export}|ConvertTo-Json -Compress
''',data,timeout=180)
    verified=json.loads(result)
    if verified.get('configured') is not True or verified.get('verified') is not True:
        raise ValueError('Firewall configuration was not verified')
    return verified
