# NAPS diagnostics

Run from the engine repository:

```powershell
dotnet run --project ProsperoPkgTool.Diagnostics -c Release -- "C:\path\game.pkg" --verify > report.json
```

For a custom passcode, place it after the package path and before `--verify`.
Omit `--verify` to dump raw NAPS only, including packages whose logical mount cannot decode.

The JSON includes header counts, raw 9-byte records and all decoded RUN/STD fields.
Verification adds dialect diagnostics, logical mount size, block-kind counts, complete file
manifest, and SHA-256 of /uroot/eboot.bin when present. It uses lazy reads, never extracts the
package, and does not allocate the entire mount. Verification failure preserves the raw dump,
adds the original error to the JSON and returns exit code 1.

Compare Sony, PPT, and LPP reports by record index and normalized file manifest. Keep real
game packages private. Unknown predictor/layout variants must be investigated from observed
bytes rather than assumed from a different builder version.
