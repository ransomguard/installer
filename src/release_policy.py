"""Distribution gates. Manifest claims never substitute for Windows trust checks."""
import json
from pathlib import Path

SERVICES = ('Anti_Ransom_Driver', 'Anti_Ransom_FsFilter')

def check_channel(manifest, info, request, payload, powershell):
    channel = manifest.get('channel')
    if channel == 'internal-test':
        if request.get('internal_test') is not True or request.get('acknowledge_pc_wide_containment') is not True:
            raise ValueError('시험용 PC 사용과 PC 전체 통신 제한 가능성에 대한 명시적 확인이 필요합니다.')
        # setup_engine's read-only preflight also requires TESTSIGNING and
        # Secure Boot off. Windows itself enforces the embedded signature.
        from readiness import require_ready
        require_ready(info.get('readiness',{}),channel)
        return {'channel':channel,'windows_signature_enforcement':True,'security_settings_changed':False}
    if channel == 'isolated-lab':
        model = ' '.join(str(v) for v in info['computer'].values()).lower()
        if request.get('isolated_lab') is not True or not any(v in model for v in ('vmware','virtual','kvm','qemu')):
            raise ValueError('시험 서명 패키지는 승인한 시험 VM에서만 설치할 수 있습니다.')
        return {'channel': channel, 'windows_signature_enforcement': True}
    if channel != 'internal-preview' or request.get('internal_test') is not True:
        raise ValueError('비공개 내부 시험 배포 확인이 필요합니다.')
    # Check signed bytes and a trusted Microsoft publisher, not microsoft_signed:true.
    files = []
    for name in SERVICES:
        for suffix in ('.sys', '.cat'):
            path = Path(payload)/'drivers'/name/(name+suffix)
            if not path.is_file():
                raise ValueError('Microsoft 서명된 SYS/CAT 패키지가 필요합니다: '+name)
            files.append(str(path))
        if not (Path(payload)/'drivers'/name/(name+'.inf')).is_file():
            raise ValueError('INF 패키지가 없습니다: '+name)
    result = json.loads(powershell(r'''$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
@($i.files|ForEach-Object{
 $s=Get-AuthenticodeSignature -LiteralPath $_
 @{path=$_;status=[string]$s.Status;subject=[string]$s.SignerCertificate.Subject}
})|ConvertTo-Json -Compress''', {'files':files}))
    if len(result) != len(files) or any(x['status'] != 'Valid' or
            'CN=Microsoft Windows Hardware Compatibility Publisher' not in x['subject'] or
            'O=Microsoft Corporation' not in x['subject'] for x in result):
        raise ValueError('Microsoft 드라이버 서명 검증에 실패했습니다. Windows 보안 설정은 변경하지 않았습니다.')
    # DriverStore installation and the kernel still enforce their own policies.
    return {'channel':channel, 'signatures':result, 'windows_signature_enforcement':True}

def driver_store(operation, inf):
    import ctypes as C
    from ctypes import wintypes as W
    if operation not in ('install','uninstall'):
        raise ValueError('Invalid driver store operation')
    lib = C.WinDLL('newdev.dll', use_last_error=True)
    fn = getattr(lib, 'DiInstallDriverW' if operation == 'install' else 'DiUninstallDriverW')
    fn.argtypes = [W.HWND,W.LPCWSTR,W.DWORD,C.POINTER(W.BOOL)]
    fn.restype = W.BOOL
    reboot = W.BOOL()
    if not fn(None,str(Path(inf).resolve()),0,C.byref(reboot)):
        raise C.WinError(C.get_last_error())
    return {'operation':operation, 'inf':str(Path(inf).resolve()), 'reboot_required':bool(reboot.value)}
