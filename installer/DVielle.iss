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
AppName=DVielle
AppVersion={#AppVersion}
AppVerName=DVielle {#AppVersion}
AppPublisher=Ravikant R. T.
AppPublisherURL=https://github.com/DVILLIE/VIGILLANCE
AppSupportURL=https://github.com/DVILLIE/VIGILLANCE
AppCopyright=Copyright (c) 2026 Ravikant R. Tayade / KT Trading System
VersionInfoVersion={#VersionInfoVersion}
VersionInfoProductName=DVielle
VersionInfoDescription=DVielle setup (official Python 3.12 bootstrap plus the Limited installer)
DefaultDirName={autopf}\DVielle
CreateAppDir=no
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
Uninstallable=no
CreateUninstallRegKey=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
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
Source: "{#PythonInstaller}"; DestDir: "{tmp}"; DestName: "python-3.12.10-amd64.exe"; Flags: ignoreversion

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  Params: String;
begin
  if CurStep <> ssPostInstall then
    Exit;
  Params :=
    '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}\DViellePayload\installer\bootstrap-dvielle.ps1') + '" ' +
    '-SourceRoot "' + ExpandConstant('{tmp}\DViellePayload') + '" ' +
    '-InstallDir "C:\DVILLIE" ' +
    '-PythonInstaller "' + ExpandConstant('{tmp}\python-3.12.10-amd64.exe') + '"';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params, '', SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode) then
  begin
    MsgBox('Could not start the DVielle installer.', mbError, MB_OK);
    Abort;
  end;
  if ResultCode <> 0 then
  begin
    MsgBox('DVielle installation failed with exit code ' + IntToStr(ResultCode) + '. The logon task was not set to a higher run level by this setup.', mbError, MB_OK);
    Abort;
  end;
end;
