# ProsperoPkgTool

ProsperoPkgTool is a .NET 10 CLI and Windows GUI for PS5 publishing projects
and package workflows. The first stable backend invokes a user-supplied
`prospero-pub-cmd.exe`; Sony binaries are not included or redistributed.

The architecture reserves native container backends for Sony PKG, FFPKG,
FFPFSC, raw exFAT, and source folders. Native PS5 package creation remains
experimental until its output passes Sony tooling and console tests.

## Build

```powershell
dotnet build .\ProsperoPkgTool.slnx -c Release
dotnet test .\ProsperoPkgTool.Tests\ProsperoPkgTool.Tests.csproj -c Release
```

## Configure the Sony tool

Pass the executable explicitly:

```powershell
ProsperoPkgTool.exe --tool "C:\path\prospero-pub-cmd.exe" tool-version
```

Or set `PROSPERO_PUB_CMD` to the full executable path. The application also
checks its own directory, `PATH`, and the standard SCE Publishing Tools
installation directory.

## Initial commands

```text
commands        Show the complete registered Sony command surface
formats         Show current and planned container backends
tool-path       Resolve prospero-pub-cmd.exe
tool-version    Run the Sony version command
registry-check  Compare the registry with the installed Sony tool
gp5gen          Generate a deterministic GP5 from an unpacked title folder
gp5info         Show native GP5 project information
gp5validate     Validate GP5 structure, metadata, chunks, paths, and sources
gp5format       Parse and deterministically rewrite a GP5 to a separate file
source-validate Validate param.json, PlayGo, required files, and source tree
playgo-info     Strictly inspect a PS5 playgo-chunk.dat
info            Friendly alias for img_info
list            Friendly alias for img_file_list
extract         Friendly alias for img_extract
verify          Friendly alias for img_verify
sony <command>  Invoke a registered Sony command
sony raw ...    Raw pass-through for future or version-specific options
```

Every Sony 1.21 command can also be invoked directly by its original name.

To include the live Sony registry integration test, set
`PROSPERO_PUB_CMD_TEST` to the full executable path before running `dotnet
test`. The test compares all discovered commands and options with the shared
registry used by both the CLI and GUI.
