# ProsperoPkgTool

ProsperoPkgTool is a clean-room, fully native .NET 10 toolkit for reading and working
with PS5 (Prospero) packages. It contains **no Sony software** and **no third-party GPL
code**: every package parser, cryptographic primitive, and filesystem reader is implemented
from scratch from independent reverse-engineering findings.

The long-term goal is to **produce debug PS5 packages that install and run on a
jailbroken console**, replacing Sony's `prospero-pub-cmd.exe` entirely for that workflow.
It does not attempt to pass Sony's official publishing validation (which requires Sony's
private keys and is out of scope).

## Status

The native **reader** is implemented and verified byte-exact against a real Sony-built
debug package:

- FIH/CNT header parsing (mixed-endian) and segment geometry reconstruction.
- Content key derivation (`ComputeKeys` / EKPFS) from a content id + 32-character passcode.
- The outer-PFS AES-128-XTS key ladder and sector-numbering scheme.
- Outer superblock location, ICV (SHA3-256) verification, and full outer-PFS decryption.
- `sce_sys/keystone` validation (v2/v3 HMAC keys).

Native **creation** of installable packages is not yet implemented. Full inner-image
(Kraken-compressed) decoding — needed to list/extract individual files inside
`pfs_image.dat` — is the next milestone.

## Build

```powershell
dotnet build .\ProsperoPkgTool.slnx -c Release
dotnet test .\ProsperoPkgTool.Tests\ProsperoPkgTool.Tests.csproj -c Release
```

No git submodules or external native dependencies are required.

## Commands

### Native package reading (no Sony tool required)

```powershell
# Identify a finalized-debug, finalized-retail, or bare CNT container
ProsperoPkgTool.exe pkg-detect .\title.pkg

# Read FIH/CNT metadata and segment geometry
ProsperoPkgTool.exe native-info .\title.pkg

# Validate unkeyed structure and segment bounds
ProsperoPkgTool.exe native-validate .\title.pkg

# List CNT metadata records
ProsperoPkgTool.exe native-entries .\title.pkg

# Derive keys from the passcode, verify the superblock, decrypt the outer PFS
ProsperoPkgTool.exe native-decrypt .\title.pkg --passcode 00000000000000000000000000000000 --out .\inner.bin
```

`native-decrypt` derives the EKPFS from the package content id and the supplied passcode,
verifies the outer superblock ICV, and decrypts the inner image. A correct passcode yields
a valid superblock and a recognizable keystone; the command reports success only when both
checks pass.

### GP5 and source tools

```powershell
ProsperoPkgTool.exe gp5gen <source-folder> [--out <file>] [--passcode <32>] [--force]
ProsperoPkgTool.exe gp5info <project.gp5>
ProsperoPkgTool.exe gp5validate <project.gp5>
ProsperoPkgTool.exe gp5format <input.gp5> --out <output.gp5> [--force]
ProsperoPkgTool.exe source-validate <source-folder>
ProsperoPkgTool.exe playgo-info <playgo-chunk.dat>
```

### Package creation (debug fPKG)

```powershell
# Build a debug base/application package from a source folder or GP5 manifest
ProsperoPkgTool.exe img_create <source-folder | project.gp5> --out .\title.pkg --passcode <32>

# Convert a decrypted backup: substitute raw ELF modules, fake-sign, and report launch-readiness
ProsperoPkgTool.exe convert <backup-folder> --out .\title.pkg --passcode <32>
```

`convert` stages the backup (excluding its `decrypted/` subtree), replaces each signed module with
its raw ELF copy, builds through the same pipeline as `img_create`, and prints the module
classification plus a launch-readiness verdict. A genuine signed module with no decrypted copy is
packed unchanged and reported as unresolved; the command exits `5` when the result is not
launch-ready.

### Misc

```powershell
ProsperoPkgTool.exe formats   # list supported/planned container backends
```

## GUI

`ProsperoPkgTool.Gui` is a small Windows Forms front end that drives the same native CLI:
package inspection, CNT entry listing, and outer-PFS decryption from the Package tab, plus
GP5/source utilities from the Tools tab. F5 runs the selected operation, Escape cancels it.

## Architecture

| Area | Location | Notes |
|---|---|---|
| Crypto primitives | `ProsperoPkgTool/Crypto/` | SHA3-256 (clean-room Keccak), AES-128-XTS, key derivation, keystone |
| Container parsing | `ProsperoPkgTool/Containers/` | FIH/CNT reader, outer-PFS reader |
| Native operations | `ProsperoPkgTool/Native/` | `CleanRoomDecrypt` (outer-PFS decrypt) |
| GP5 project model | `ProsperoPkgTool/Gp5/` | GP5 XML read/validate/generate, PlayGo, param.json, source validation |
| CLI | `ProsperoPkgTool/CliApplication.cs` | command routing |
| GUI | `ProsperoPkgTool.Gui/` | native-only operations |

The crypto layer is validated by `ProsperoPkgTool.Tests/ProsperoCryptoTests.cs`, which
asserts every derived key and digest byte-exact against a known reference package
(`ProsperoPkgTool.Tests/Fixtures/test.pkg`).

## Licensing / provenance

ProsperoPkgTool is original, clean-room work. An earlier iteration of this repository
briefly linked the GPL-3.0 `LibProsperoPKG` library and wrapped Sony's
`prospero-pub-cmd.exe`; both have been **completely removed** so the project carries no
copyleft or proprietary-binary obligations. Reverse-engineering findings used to implement
the format live separately and are not redistributed here.

## Credits

- SvenGDK
- Sony <3
