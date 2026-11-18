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
$existing=Get-NetFirewallRule -Name 'RansomGuard-JEV-Only-HTTPS' -ErrorAction SilentlyContinue
if($existing){throw 'Existing JEV policy requires review; do not overwrite it'}
$export=Join-Path $i.backup 'firewall-before.wfw'
& netsh.exe advfirewall export $export|Out-Null;if($LASTEXITCODE){throw 'Firewall backup failed'}
$hosts=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$old=[IO.File]::ReadAllText($hosts);[IO.File]::WriteAllText((Join-Path $i.backup 'hosts-before.txt'),$old)
if($old -match '(?im)^\s*\S+\s+api\.typesafe\.ai(?:\s|$)'){throw 'Existing JEV hosts mapping requires review'}
$allows=@(Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True)
@($allows|Select-Object -ExpandProperty Name)|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $i.backup 'outbound-allows-before.json')
if(@($i.addresses).Count -gt 0){
 $mapping="`r`n# RansomGuard JEV fixed endpoint`r`n"+((@($i.addresses)|ForEach-Object {$_+' api.typesafe.ai'}) -join "`r`n")+"`r`n"
 [IO.File]::AppendAllText($hosts,$mapping,[Text.Encoding]::ASCII)
 New-NetFirewallRule -Name 'RansomGuard-JEV-Only-HTTPS' -DisplayName 'RansomGuard JEV bridge only (fixed API)' -Direction Outbound -Action Allow -Enabled True -Program $i.bridge -Protocol TCP -RemotePort 443 -RemoteAddress $i.addresses -Profile Any|Out-Null
}
foreach($r in $allows){Disable-NetFirewallRule -Name $r.Name|Out-Null}
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
@{configured=$true;addresses=$i.addresses;jev_exception_ready=(@($i.addresses).Count -gt 0);policy='Block outbound; only resolved JEV bridge HTTPS may be allowed';previous_policy_export=$export}|ConvertTo-Json -Compress
''',data,timeout=90)
    return json.loads(result)
