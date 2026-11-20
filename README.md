# Ransom0 통합 시험 설치본

## 다운로드 선택

- **설치:** Releases의 `Ransom0-Install.zip` — 통합 설치 EXE, 점검 도구, VM/호스트 시험 가이드 포함.
- **시험:** Releases의 `Ransom0-TestLab.zip` — 시험 실행 도구, 사용법, 검증결과 포함.
- ZIP을 먼저 풀고 실행하세요. Source code ZIP은 설치 파일이 아닙니다.
- 복구 시험은 6번으로 문서 생성 → 설정에서 `C:\ProgramData\Ransom0TestLab\Protected`를 복구 범위로 적용 → 7·8·9번 실행 순서입니다.
- Rule1001 후속 UI 수정은 https://github.com/ransomguard/ui/pull/4 에서 검토합니다. Preview15 설치 EXE에는 아직 포함되지 않습니다.


[Preview 15 다운로드](https://github.com/ransomguard/installer/releases/tag/v0.6.0-preview.15)

Ransom0 0.6.0-preview.15 — 내부 시험용 통합 설치본

Ransom0-Setup.exe 하나에 Python·커널 드라이버·복구·UI·방화벽이 포함됩니다. 다른 저장소를 따로 설치하거나 파이프라인을 수동 연결할 필요가 없습니다.
1. 해당 VM/호스트 시험 가이드의 사전 준비를 완료합니다. 시험 서명 드라이버이므로 일반 PC 기본 보안 환경의 정식 배포판은 아닙니다.
2. Ransom0-Setup.exe의 설치/업데이트를 실행한 뒤 실행을 누릅니다.
3. 대시보드 설정에서 복구 범위와 자신의 JEV API 키를 입력합니다. 키는 배포 파일에 포함하지 않습니다.
4. 평상시 기존 인터넷 설정을 유지합니다. 자동 대응 시 격리될 수 있으며 실패/검토 hold는 임의 해제하지 않습니다.
5. Ransom0-TestLab.zip은 선택 사항인 독립 시험 도구입니다. 시험 VM에서 풀고 Start-TestLab.cmd를 관리자 실행합니다. 도구 안의 사용법과 검증결과를 먼저 읽으세요.

기존 내부 서비스/설치 폴더 이름 RansomGuard는 업그레이드 호환성을 위해 유지합니다. 화면/설치기/바로가기 제품명은 Ransom0입니다.
Secure Boot·시험 서명·Windows 암호·VM 어댑터 설정을 설치기가 자동 변경하지 않습니다.
유실 기록은 유지합니다. 12만 회 시험 통과가 무제한 부하/모든 환경에서 유실 0을 보증하지 않습니다. 원본 intake 버퍼 상한은384MiB(최대131072건)이며 UI/DB/분석 메모리는 별도입니다.
소스 ZIP은 실행 설치본이 아닙니다. Releases의 EXE를 받으세요.


소스: `src/` 설치기, `backend/` 포함 복구 소스, `testlab/` 독립 시험 도구. `build-reference.py`는 기존 payload/드라이버 바이너리가 필요한 제작 환경의 레시피로, 저장소 하나만으로 재현되는 빌드라고 주장하지 않습니다. 실제 포함 파일은 `payload-manifest.json`으로 식별합니다.
