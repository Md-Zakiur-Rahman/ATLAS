[Setup]
AppName=ATLAS
AppVersion=1.0
DefaultDirName={autopf}\ATLAS
DefaultGroupName=ATLAS
OutputDir=installer\output
OutputBaseFilename=ATLAS_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "dist\ATLAS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "assets\first_run.flag"; DestDir: "{app}\assets"; Flags: ignoreversion

[Icons]
Name: "{group}\ATLAS"; Filename: "{app}\ATLAS.exe"
Name: "{autodesktop}\ATLAS"; Filename: "{app}\ATLAS.exe"

[Run]
Filename: "{app}\ATLAS.exe"; Description: "Launch ATLAS"; Flags: nowait postinstall skipifsilent