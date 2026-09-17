# Native-span compatibility regression

Run `dotnet test ProsperoPkgTool.CompatibilityTests -c Release`.

`Fixtures/lpp120-mixed.pkg` is a generated test package, not a game dump. It was built by the
vendored LibProsperoPkg 1.2.0 binary (SHA-256
`D04D8660FDB0047386C94F727EEC32413334353329CC9C18CE8FC7DD92D3C271`) through PS5PKGTool's
existing LppBackend, using its default compression and the all-zero passcode.

The source consists of a minimal param.json with content ID
`UP0000-PPSA12345_00-TESTPACKAGE00000`, title ID `PPSA12345`, English title `Reader fixture`,
and an 8 MiB payload.bin. The payload is initialized to zeros, its first MiB is filled using
`new Random(42).NextBytes`, and bytes from 2 MiB through 4 MiB are `(byte)(index * 31)`.
Payload SHA-256: `084B53568666B6B3BA37C3721A94E899909660B5EA03B8D4CE0A4752F9401A65`.
The builder adds its standard keystone, pfs-version.dat and right.sprx.

Expected mount: 13,238,272 bytes; 11 total PFS entries; 7 non-directory entries, including
internal metadata; 4 files below /uroot. Both materialized and lazy mounts must be byte-exact,
and every block must decode successfully.

## Observations versus the original investigation hypothesis

The raw 9-byte decoder is shared with the Sony fixture and PPT output. In this 1.2.0 sample:

- All STD KDE predictors are zero, including Kraken records. Predictor 2/4 semantics have
  therefore **not** been added based on the earlier hypothesis.
- RUN bases use `CoffsetStart256K << 18` plus the first STD's low offset. The proposed
  `TweakIdxStart << 15` interpretation does not match the observed physical bytes.
- An unmarked stored 256 KiB span has even=odd=1 and ClenEvenMinus1=131071. Its compressed
  modulo delta wraps to zero; it is not an unresolved alias.
- Encoded zero spans use the observed 8/16-byte shapes. They produce zeros while still
  advancing the physical cursor by their encoded length.
- Repeated compressed blocks can rebase to the same physical source through RUN records.

`native-span-v1` interprets these independently observed records. The existing compatible
traversal remains available. Equivalent read maps share the established path; differing maps
require a bounded lazy PFS metadata probe. If both remain valid, selection fails as ambiguous.
No LPP implementation source was used for this change.

The original Sony/PPT suite remains in the repository's existing local-only test directory.
This standalone project is tracked so the new regression does not depend on that directory.
PS5PKGTool's BackendSmoke also generates a mixed fixture with each builder and compares the
payload through both the engine and application readers.

## Indexed sparse pages (Ufouria acceptance fix)

The supplied Ufouria package contains stored-marker records, so it uses the compatible
compressed-offset interpretation rather than the unmarked native-span interpretation.
Consecutive STD deltas total 1,206,386,688 bytes, but its exact fidx mount sentinel declares
1,213,202,432 bytes. The difference is 26 inter-file sparse slots, each exactly 256 KiB.
These slots are invisible in the 18-bit STD logical offsets: adding 256 KiB preserves the
same low bits. They are not missing decompressed bytes inside partial Kraken blocks.

`indexed-coffset-v1` restores zero extents at the absolute positions implied by the u2c
acceleration table. It validates every u2c anchor, all fidx file boundaries, the exact fidx
mount end, and the rounded header page count. It leaves payload lengths and codec flags
unchanged and remaps alias source indices after inserting the zero extents. Padding only
the mount end would leave files and directories at incorrect offsets and is not used.

NumUBlocks is a rounded page count, not an exact byte length. In particular LPP Bendy's
valid mount ends 128 KiB before NumUBlocks * 256 KiB; its exact fidx sentinel agrees with
the walked length. The reader must preserve that valid tail rather than force extra bytes.

`NapsSparseIndexTests` covers one/many sparse pages, alias remapping, corrupt u2c/fidx
tables, and a generated 100-small-file package read byte-for-byte through both APIs.

Acceptance on the three private packages passed on 2026-09-17: PPT Bendy and LPP Bendy
retain matching eboot SHA-256; Ufouria's eboot and each of the 26 files immediately after
restored gaps match the original source dump. No game payload was added to the test suite.
