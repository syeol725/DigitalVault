# DigitalVault Portable

Windows 10/11 64비트용 USB 휴대형 암호화 문서 금고입니다.

## 주요 기능

- AES-256-GCM 인증 암호화
- 비밀번호 기반 키 파생: scrypt
- 문서 추가, 목록, 열기, 내보내기, 삭제
- 비밀번호 변경
- 로그인 5회 실패 시 60초 로그인 제한
- 실행 파일이 있는 폴더에 기본 금고 데이터 저장
- 작업 완료 후 계속 사용 여부 확인
- Windows용 단일 실행 파일 빌드

## 지원 파일 형식

PDF, DOCX, TXT, PPTX, XLSX, JPG, JPEG, PNG

## USB에서 사용하기

1. GitHub Actions에서 `DigitalVault-Windows-x64` 아티팩트를 다운로드합니다.
2. ZIP 파일을 압축 해제합니다.
3. 압축 해제한 `DigitalVault.exe`를 USB에 복사합니다.
4. USB에서 `DigitalVault.exe`를 실행합니다.
5. 금고 저장 폴더 입력에서 Enter를 누릅니다.
6. USB 안에 생성되는 `DigitalVaultData` 폴더에 금고 데이터가 저장됩니다.

다른 Windows 컴퓨터에서도 실행 파일과 `DigitalVaultData` 폴더를 함께 사용해야 합니다.

## Windows에서 직접 빌드하기

1. Windows 10/11 64비트와 Python을 준비합니다.
2. 저장소 폴더에서 `build_windows.bat`를 실행합니다.
3. 빌드가 성공하면 `dist\DigitalVault.exe`가 생성됩니다.

## GitHub Actions 빌드

1. 저장소의 **Actions** 탭을 엽니다.
2. **Build Windows DigitalVault** 워크플로를 선택합니다.
3. **Run workflow**를 실행합니다.
4. 실행이 완료되면 아티팩트 `DigitalVault-Windows-x64`를 다운로드합니다.

태그를 `v1.0.0` 형식으로 푸시해도 빌드가 실행됩니다.

## 보안상 주의사항

- 비밀번호를 잊으면 금고 데이터에 접근할 수 없습니다.
- `DigitalVaultData` 폴더 전체를 별도 저장장치에 백업하세요.
- 내보낸 문서는 금고 외부의 일반 파일이며 자동으로 암호화되지 않습니다.
- 문서를 열 때 임시 복호화 파일이 생성됩니다. 프로그램은 사용자가 Enter를 누른 뒤 임시 폴더 삭제를 시도하지만, 문서 앱·운영체제·백업·스왑 등이 복사본을 남길 수 있어 완전한 흔적 제거를 보장하지 않습니다.
- 로그인 제한 파일은 USB 안에 저장됩니다. 파일을 직접 수정할 수 있는 공격자를 막는 보안 경계로 간주하면 안 됩니다.
- USB를 쓰기 작업 중 분리하지 마세요.
- 이 프로그램은 백신, 백업, USB 분실 방지 기능을 대체하지 않습니다.

## 데이터 형식 안내

이 버전은 현재 제공된 새 코드의 암호화 형식을 사용합니다. 이전 버전에서 만든 금고 데이터와 호환되지 않을 수 있으므로, 기존 금고 데이터를 새 버전에서 열 수 있다고 가정하지 마세요.
