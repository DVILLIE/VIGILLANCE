; DVielle setup wrapper. Compiles to DVielle-Setup-<version>.exe.
; The wrapper does not become the product uninstaller and does not own C:\DVILLIE.
; bootstrap-dvielle.ps1 calls install-dvielle.ps1 with -RunLevel Limited only.

#ifndef AppVersion
  #error AppVersion is required. Pass /DAppVersion= from scripts/build_windows_installer.ps1.
#endif
#ifndef VersionInfoVersion
  #error VersionInfoVersion is required.
#endif
#ifndef PayloadDir
  #error PayloadDir is required.
#endif
#ifndef PythonInstaller
  #error PythonInstaller is required.
#endif
#ifndef OutputDir
  #error OutputDir is required.
#endif

[Setup]
AppId={{8F4C1A2E-6B7D-4E91-9C3A-D5E2F80B14C6}
AppName=D'Vielle
AppVersion={#AppVersion}
AppVerName=D'Vielle {#AppVersion}
AppPublisher=Ravikant R. T.
AppPublisherURL=https://github.com/DVILLIE/VIGILLANCE
AppSupportURL=https://github.com/DVILLIE/VIGILLANCE
AppCopyright=Copyright (c) 2026 Ravikant R. Tayade / KT Trading System
VersionInfoVersion={#VersionInfoVersion}
VersionInfoProductName=D'Vielle
VersionInfoDescription=D'Vielle setup (held pending protected bootstrap staging)
DefaultDirName={autopf}\DVielle
CreateAppDir=no
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
Uninstallable=no
CreateUninstallRegKey=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile=..\assets\brand\dvielle.ico
WizardStyle=modern
SetupLogging=yes
ChangesEnvironment=yes
CloseApplications=no
RestartApplications=no
OutputDir={#OutputDir}
OutputBaseFilename=DVielle-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
InfoBeforeFile=SETUP_NOTICE.txt
LicenseFile=..\LICENSE

[Files]
Source: "{#PayloadDir}/*"; DestDir: "{tmp}\DViellePayload"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#PythonInstaller}"; DestDir: "{tmp}"; DestName: "python-3.14.8-amd64.exe"; Flags: ignoreversion

[Code]
function InitializeSetup: Boolean;
begin
  { The current payload target is user-writable temporary storage. Do not
    execute an elevated script from it and then attempt an ACL preflight.
    InitializeSetup=False aborts before application-file installation:
    https://jrsoftware.org/ishelp/topic_scriptevents.htm }
  MsgBox('This setup wrapper is held until protected bootstrap staging is implemented. Use the Limited installer from a verified, protected source stage. See docs/REPAIR_INSTALL_PRIVILEGE_BOUNDARY.md.', mbError, MB_OK);
  Result := False;
end;
