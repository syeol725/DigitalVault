# DigitalVault Portable

Windows, macOS, Linux용 USB 휴대형 암호화 문서 금고 프로젝트입니다.

## 제공 기능
- AES-256-GCM 인증 암호화
- 비밀번호 기반 키 파생: scrypt
- 문서 추가 / 목록 / 열기 / 내보내기 / 삭제
- 비밀번호 변경
- 로그인 실패 횟수 제한
- 실행 파일이 있는 폴더에 기본 금고 데이터 저장
- Windows / macOS / Linux 별도 빌드

## USB 사용 방법
1. 해당 운영체제용 실행 파일을 USB에 복사합니다.
2. 실행 파일을 USB에서 실행합니다.
3. 금고 경로 질문에서 Enter를 누릅니다.
4. USB 안에 `DigitalVaultData` 폴더가 만들어집니다.
5. 처음 실행할 때 비밀번호를 만들고 문서를 저장합니다.
6. 다른 컴퓨터에서도 같은 USB의 실행 파일과 `DigitalVaultData` 폴더를 사용합니다.

**중요:** 실행 파일과 `DigitalVaultData` 폴더를 함께 이동해야 합니다. 다른 컴퓨터에서 금고 폴더를 별도로 선택하면 다른 금고가 열립니다.

## 직접 빌드
### Windows
`build_windows.bat` 실행. 결과는 `dist/DigitalVault.exe`.

### macOS / Linux
터미널에서 `./build_unix.sh` 실행. 결과는 `dist/DigitalVault`.

각 운영체제의 실행 파일은 해당 운영체제에서 빌드해야 합니다. GitHub Actions 워크플로를 사용하면 Windows, macOS, Linux 빌드를 각각 자동으로 만들 수 있습니다.

## GitHub Actions로 3종 빌드
1. 이 프로젝트 전체를 GitHub 저장소에 올립니다.
2. 저장소의 Actions 탭을 엽니다.
3. `Build portable apps` 워크플로를 선택합니다.
4. `Run workflow`를 누릅니다.
5. 완료된 실행 기록에서 다음 아티팩트를 각각 내려받습니다.
   - `DigitalVault-Windows-x64`
   - `DigitalVault-macOS`
   - `DigitalVault-Linux-x64`

GitHub Actions에서 만든 아티팩트는 빌드 결과물이며, 이 저장소 자체에 자동으로 USB에 설치되지는 않습니다.

## 보안상 유의사항
- 비밀번호를 잊으면 복구할 수 없습니다. 비밀번호를 안전한 별도 장소에 보관하세요.
- `DigitalVaultData` 폴더 전체를 정기적으로 백업하세요. 백업도 암호화된 상태로 보관해야 합니다.
- 로그인 제한 파일은 USB에 저장되므로 물리적으로 파일을 수정하는 공격자에 대한 강제 지연 장치로 간주하면 안 됩니다. 실제 보안은 강한 비밀번호와 AES-GCM 암호화에 의존합니다.
- 문서를 열 때 임시 복호화 파일이 만들어집니다. 프로그램은 종료 후 삭제를 시도하지만, 운영체제·문서 앱·백업·스왑이 복사본을 남길 수 있어 완전한 흔적 제거를 보장하지 않습니다.
- USB를 안전하게 꺼내고, 쓰기 작업 중 분리하지 마세요.
- 이 프로그램은 악성코드 검사, 백업, USB 분실 방지 기능을 대체하지 않습니다.
- 현재 빌드는 콘솔 기반이며, Windows x64 / macOS 빌드 머신 아키텍처 / Linux x64 기준입니다. 다른 CPU 아키텍처는 해당 환경에서 별도 빌드해야 합니다.

## 지원 파일 형식
PDF, DOCX, TXT, PPTX, XLSX, JPG, JPEG, PNG
