"""Fail before installation changes on unsupported PCs. Never change boot policy."""
import json, subprocess
from pathlib import Path

def collect(payload):
    result=subprocess.run([str(Path(payload)/'RansomGuard-Check.exe'),'--json'],capture_output=True,timeout=30)
    if result.returncode:
        raise ValueError('설치 전 시스템 검사를 완료하지 못했습니다.')
    return json.loads(result.stdout.decode('utf-8-sig'))

def blockers(info, channel, *, require_admin=True):
    problems=[]
    if require_admin and info.get('elevated') is not True:problems.append('설치에는 관리자 승인이 필요합니다.')
    if info.get('architecture')!='x64':problems.append('현재 드라이버는 x64 전용입니다. ARM64/x86은 지원하지 않습니다.')
    if int(info.get('build') or 0)<19041:problems.append('Windows 빌드 19041 이상이 필요합니다.')
    if info.get('vss_disabled'):problems.append('Windows VSS 서비스가 사용 안 함 상태입니다.')
    if info.get('altitude_scan_complete') is not True:problems.append('미니필터 altitude 충돌 검사를 완료하지 못했습니다.')
    if info.get('altitude_conflicts'):problems.append('다른 미니필터와 시험 altitude가 충돌합니다.')
    if info.get('system_filesystem')!='NTFS':problems.append('현재 설치판에는 NTFS 시스템 드라이브가 필요합니다.')
    if int(info.get('system_disk_free_bytes') or 0)<6*1024**3:problems.append('프로그램과 복구 준비를 위한 여유 공간이 부족합니다 (최소 6GiB).')
    if channel in ('isolated-lab','internal-test'):
        if info.get('test_signing') is not True:problems.append('시험 서명 드라이버를 허용하도록 별도로 준비된 시험 환경이 아닙니다. 보안 설정은 자동 변경하지 않습니다.')
        if info.get('secure_boot') is not False:problems.append('시험판의 보안 부팅 조건을 확인하지 못했습니다. 일반 PC용 Microsoft 서명판이 필요합니다.')
    return problems

def require_ready(info, channel):
    reasons=blockers(info,channel)
    if reasons:raise ValueError(' / '.join(reasons))
