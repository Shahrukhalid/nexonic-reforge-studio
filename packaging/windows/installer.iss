; Inno Setup script -> Nexonic_ReForge_Studio_Windows_x64_Setup.exe
#define AppVer GetEnv("REFORGE_VERSION")
#if AppVer == ""
  #define AppVer "0.4.0"
#endif
[Setup]
AppId={{6B3F3C1E-6A57-4E8B-9D0B-5E2C1B7A9F10}
AppName=Nexonic ReForge Studio
AppVersion={#AppVer}
AppPublisher=Nexonic Technologies
DefaultDirName={autopf}\Nexonic ReForge Studio
DefaultGroupName=Nexonic ReForge Studio
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=Nexonic_ReForge_Studio_Windows_x64_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog
[Files]
Source: "..\..\dist\NexonicReForgeStudio\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "..\..\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{group}\Nexonic ReForge Studio"; Filename: "{app}\NexonicReForgeStudio.exe"
Name: "{autodesktop}\Nexonic ReForge Studio"; Filename: "{app}\NexonicReForgeStudio.exe"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
[Run]
Filename: "{app}\NexonicReForgeStudio.exe"; Description: "Launch Nexonic ReForge Studio"; Flags: nowait postinstall skipifsilent
