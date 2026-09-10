#requires -Version 5.1
<#
.SYNOPSIS
    End-to-end cross-validation harness for ProsperoPkgTool.

.DESCRIPTION
    Builds the tool, runs its unit tests, generates real .pkg artifacts from a deterministic
    source tree, then validates those artifacts with independent readers:

      * ProsperoPkgTool's own img_verify / img_extract
      * the official prospero-pub-cmd.exe (img_info structural parse)
      * the LibProsperoPkg reference engine, used as an oracle to (a) extract the inner-PFS
        tree and (b) extract + decrypt protected CNT entries

    The reference oracle is compiled on the fly from an embedded C# source into $WorkDir\oracle.
    If its assembly (LibProsperoPkg.dll) cannot be found, that phase is reported as SKIP.

    Exit code is 0 when every executed check passed, otherwise non-zero.

.PARAMETER Configuration
    Build configuration (Release or Debug). Default: Release.

.PARAMETER WorkDir
    Scratch directory for the fixture, packages and oracle build. Default: %TEMP%\ProsperoPkgTool-CrossValidate.

.PARAMETER PubCmd
    Path to the official prospero-pub-cmd.exe. Default: the known developer location.

.PARAMETER ReferenceDir
    Directory containing LibProsperoPkg.dll (+ BCnEncoder.dll, CommunityToolkit.HighPerformance.dll).

.PARAMETER SkipTests
    Skip the dotnet test phase.

.PARAMETER SkipReference
    Skip the LibProsperoPkg oracle phase entirely.

.PARAMETER KeepArtifacts
    Do not delete $WorkDir on exit.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\tools\CrossValidate.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')] [string] $Configuration = 'Release',
    [string] $WorkDir      = (Join-Path $env:TEMP 'ProsperoPkgTool-CrossValidate'),
    [string] $PubCmd       = 'C:\Users\User\source\repos\PS5 Fake Pkg Tools\prospero-pub-cmd.exe',
    [string] $ReferenceDir = 'C:\Users\User\Desktop\fpkg-gui\app',
    [switch] $SkipTests,
    [switch] $SkipReference,
    [switch] $KeepArtifacts
)

$ErrorActionPreference = 'Stop'
$RepoRoot  = Split-Path -Parent $PSScriptRoot
$CliExe    = Join-Path $RepoRoot "ProsperoPkgTool\bin\$Configuration\net10.0\ProsperoPkgTool.exe"
$TestProj  = Join-Path $RepoRoot 'ProsperoPkgTool.Tests\ProsperoPkgTool.Tests.csproj'
$Solution  = Join-Path $RepoRoot 'ProsperoPkgTool.slnx'
$ContentId = 'IV0001-PPSA01234_00-TESTPACKAGE00001'
$Passcode  = '12345678923456789102123901202333'

$script:Results  = @()
$script:Failures = 0

function Add-Result {
    param([string] $State, [string] $Name, [string] $Detail = '')
    $script:Results += [pscustomobject]@{ State = $State; Name = $Name; Detail = $Detail }
    if ($State -eq 'FAIL') { $script:Failures++ }
    $fore = switch ($State) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'SKIP' { 'DarkYellow' } default { 'Gray' } }
    Write-Host ("  {0,-4} {1}" -f $State, $Name) -ForegroundColor $fore
    if ($Detail) { Write-Host ("       {0}" -f $Detail) -ForegroundColor DarkGray }
}

function Invoke-Process {
    param([string] $Exe, [string[]] $ArgList, [string] $WorkingDirectory)
    Push-Location
    try {
        if ($WorkingDirectory) { Set-Location -LiteralPath $WorkingDirectory }
        $output = & $Exe @ArgList 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    }
    finally { Pop-Location }
}

function Test-SameFile {
    param([string] $A, [string] $B)
    $fa = Get-Item -LiteralPath $A -ErrorAction Stop
    $fb = Get-Item -LiteralPath $B -ErrorAction Stop
    if ($fa.Length -ne $fb.Length) { return $false }
    return (Get-FileHash -LiteralPath $A -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $B -Algorithm SHA256).Hash
}

function Compare-ExtractedTree {
    param([string] $ExtractRoot, [string] $SourceRoot, [string] $Label)
    $checked = 0
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($f in Get-ChildItem -LiteralPath $ExtractRoot -Recurse -File) {
        $rel = $f.FullName.Substring($ExtractRoot.Length).TrimStart('\', '/')
        $src = Join-Path $SourceRoot $rel
        if (Test-Path -LiteralPath $src) {
            $checked++
            if (-not (Test-SameFile $f.FullName $src)) { $bad.Add($rel) }
        }
    }
    if ($bad.Count -gt 0) {
        Add-Result FAIL $Label ("{0} mismatched: {1}" -f $bad.Count, ($bad -join ', '))
    }
    elseif ($checked -eq 0) {
        Add-Result FAIL $Label 'no overlapping files were found to validate'
    }
    else {
        Add-Result PASS $Label "$checked extracted files are byte-identical to the source"
    }
}

function New-Fixture([string] $Root) {
    $sce = Join-Path $Root 'sce_sys'
    $nested = Join-Path $Root 'nested\deep'
    New-Item -ItemType Directory -Force -Path $sce, $nested | Out-Null

    [IO.File]::WriteAllBytes((Join-Path $Root 'eboot.bin'), [byte[]] (0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0))

    $large = New-Object byte[] 0xE1000
    for ($i = 0; $i -lt $large.Length; $i++) { $large[$i] = [byte] (($i * 17 + 3) -band 0xFF) }
    [IO.File]::WriteAllBytes((Join-Path $Root 'large.bin'), $large)

    $nestedBytes = New-Object byte[] 0x3000
    for ($i = 0; $i -lt $nestedBytes.Length; $i++) { $nestedBytes[$i] = [byte] (($i * 29 + 11) -band 0xFF) }
    [IO.File]::WriteAllBytes((Join-Path $nested 'structured.bin'), $nestedBytes)

    $tinyPng = 'iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAGklEQVR4XmNk+M/wX+AD+w8YZnE4IPOANAEAMSwf9B7uakAAAAAASUVORK5CYII='
    [IO.File]::WriteAllBytes((Join-Path $sce 'icon0.png'), [Convert]::FromBase64String($tinyPng))

    # Protected outer CNT entry with an unaligned payload (real nptitle.dat size is 0x402).
    $nptitle = New-Object byte[] 0x402
    for ($i = 0; $i -lt $nptitle.Length; $i++) { $nptitle[$i] = [byte] (($i * 7 + 1) -band 0xFF) }
    [IO.File]::WriteAllBytes((Join-Path $sce 'nptitle.dat'), $nptitle)

    $param = [ordered]@{
        titleId                 = 'PPSA01234'
        contentId               = $ContentId
        contentVersion          = '01.000.000'
        applicationCategoryType = 0
        pubtools                = [ordered]@{ creationDate = '2026-08-25 12:00:00' }
    }
    [IO.File]::WriteAllText((Join-Path $sce 'param.json'), ($param | ConvertTo-Json -Depth 5))
}

function New-Oracle([string] $Root, [string] $RefDir) {
    $dir = Join-Path $Root 'oracle'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $csproj = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0-windows</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AssemblyName>Oracle</AssemblyName>
    <EnableDefaultCompileItems>true</EnableDefaultCompileItems>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="LibProsperoPkg"><HintPath>__REF__\LibProsperoPkg.dll</HintPath></Reference>
    <Reference Include="BCnEncoder"><HintPath>__REF__\BCnEncoder.dll</HintPath></Reference>
    <Reference Include="CommunityToolkit.HighPerformance"><HintPath>__REF__\CommunityToolkit.HighPerformance.dll</HintPath></Reference>
  </ItemGroup>
</Project>
'@
    Set-Content -LiteralPath (Join-Path $dir 'Oracle.csproj') -Value ($csproj.Replace('__REF__', $RefDir)) -Encoding UTF8

    $program = @'
using LibProsperoPkg.PKG;

if (args.Length < 2)
{
    Console.Error.WriteLine("usage: Oracle info <pkg> | extract-inner <pkg> <outdir> <passcode> | extract-cnt <pkg> <outdir> <passcode>");
    return 2;
}

switch (args[0])
{
    case "info":
        Console.WriteLine(ProsperoPackageArchive.Inspect(args[1]));
        return 0;
    case "extract-inner":
        if (args.Length < 4) return 2;
        foreach (string f in ProsperoPackageArchive.ExtractInnerFiles(args[1], args[2], args[3], decompressFiles: true))
            Console.WriteLine(f);
        return 0;
    case "extract-cnt":
        if (args.Length < 4) return 2;
        foreach (string f in ProsperoPackageArchive.ExtractCntEntries(args[1], args[2], args[3], includeEncrypted: true))
            Console.WriteLine(f);
        return 0;
    default:
        Console.Error.WriteLine("unknown mode: " + args[0]);
        return 2;
}
'@
    Set-Content -LiteralPath (Join-Path $dir 'Program.cs') -Value $program -Encoding UTF8

    $build = Invoke-Process 'dotnet' @('build', (Join-Path $dir 'Oracle.csproj'), '-c', 'Release', '--nologo', '-v', 'q')
    if ($build.ExitCode -ne 0) {
        Add-Result FAIL 'Reference oracle build' ($build.Output.Trim() | Select-Object -First 1)
        return $null
    }
    return (Join-Path $dir "bin\Release\net10.0-windows\Oracle.exe")
}

# ---------------------------------------------------------------------------- main

Write-Host ''
Write-Host 'ProsperoPkgTool cross-validation' -ForegroundColor Cyan
Write-Host ("  repo       : {0}" -f $RepoRoot)
Write-Host ("  config     : {0}" -f $Configuration)
Write-Host ("  work dir   : {0}" -f $WorkDir)
Write-Host ''

if (Test-Path -LiteralPath $WorkDir) { Remove-Item -Recurse -Force -LiteralPath $WorkDir }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$src = Join-Path $WorkDir 'src'
New-Fixture $src

Write-Host 'Phase 1: build + unit tests' -ForegroundColor Cyan
$build = Invoke-Process 'dotnet' @('build', $Solution, '-c', $Configuration, '--nologo', '-v', 'q')
if ($build.ExitCode -eq 0) { Add-Result PASS 'dotnet build' '0 warnings / 0 errors' }
else { Add-Result FAIL 'dotnet build' ($build.Output.Trim() | Select-Object -First 1) }

if (-not $SkipTests) {
    $test = Invoke-Process 'dotnet' @('test', $TestProj, '-c', $Configuration, '--no-build', '--nologo')
    $summary = ($test.Output -split "`n" | Where-Object { $_ -match 'Passed!|Failed!|Passed:' } | Select-Object -Last 1)
    if ($test.ExitCode -eq 0) { Add-Result PASS 'dotnet test' ($summary -replace '\s+', ' ').Trim() }
    else { Add-Result FAIL 'dotnet test' ($summary | Select-Object -First 1) }
}

if (-not (Test-Path -LiteralPath $CliExe)) {
    Add-Result FAIL 'CLI executable' "not found: $CliExe"
    Write-Host ''
    Write-Host ("FAILURES: {0}" -f $script:Failures) -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host 'Phase 2: generate packages + self-verify' -ForegroundColor Cyan
$packages = @{
    'plain'  = Join-Path $WorkDir 'plain.pkg'
    'kraken' = Join-Path $WorkDir 'kraken.pkg'
}
foreach ($entry in $packages.GetEnumerator()) {
    $out = $entry.Value
    $makeArgs = @('img_create', $src, '--out', $out, '--passcode', $Passcode)
    if ($entry.Key -eq 'kraken') { $makeArgs += @('--compression', 'kraken') }

    $make = Invoke-Process $CliExe $makeArgs
    if ($make.ExitCode -eq 0 -and (Test-Path -LiteralPath $out)) {
        Add-Result PASS ("img_create ({0})" -f $entry.Key) ("{0:N0} bytes" -f (Get-Item -LiteralPath $out).Length)
    }
    else {
        Add-Result FAIL ("img_create ({0})" -f $entry.Key) 'non-zero exit'
        continue
    }

    $verify = Invoke-Process $CliExe @('img_verify', $out, '--passcode', $Passcode)
    if ($verify.ExitCode -eq 0) {
        Add-Result PASS ("img_verify ({0})" -f $entry.Key) 'all supported checks passed'
    }
    else {
        Add-Result FAIL ("img_verify ({0})" -f $entry.Key) 'img_verify reported a failure'
    }

    $extractDir = Join-Path $WorkDir ("extract-" + $entry.Key)
    $extract = Invoke-Process $CliExe @('img_extract', $out, $extractDir, '--passcode', $Passcode)
    if ($extract.ExitCode -eq 0) { Compare-ExtractedTree $extractDir $src ("img_extract round-trip ({0})" -f $entry.Key) }
    else { Add-Result FAIL ("img_extract ({0})" -f $entry.Key) 'non-zero exit' }
}

Write-Host ''
Write-Host 'Phase 3: official prospero-pub-cmd (independent parser)' -ForegroundColor Cyan
if (Test-Path -LiteralPath $PubCmd) {
    foreach ($entry in $packages.GetEnumerator()) {
        $info = Invoke-Process $PubCmd @('img_info', $entry.Value)
        $hasId = $info.Output -match [regex]::Escape($ContentId)
        if ($info.ExitCode -eq 0 -and $hasId) {
            Add-Result PASS ("prospero-pub-cmd img_info ({0})" -f $entry.Key) "parsed content id $ContentId"
        }
        else {
            Add-Result FAIL ("prospero-pub-cmd img_info ({0})" -f $entry.Key) "exit $($info.ExitCode), content id not recognized"
        }
    }
}
else {
    Add-Result SKIP 'prospero-pub-cmd img_info' "not found: $PubCmd"
}

Write-Host ''
Write-Host 'Phase 4: LibProsperoPkg reference engine (independent reader)' -ForegroundColor Cyan
$refDll = Join-Path $ReferenceDir 'LibProsperoPkg.dll'
if ($SkipReference) {
    Add-Result SKIP 'reference engine' 'skipped by -SkipReference'
}
elseif (-not (Test-Path -LiteralPath $refDll)) {
    Add-Result SKIP 'reference engine' "LibProsperoPkg.dll not found in $ReferenceDir"
}
else {
    $oracle = New-Oracle $WorkDir $ReferenceDir
    if ($oracle -and (Test-Path -LiteralPath $oracle)) {
        Add-Result PASS 'reference oracle build' $oracle

        # 4a. Inner-PFS tree extraction, both compression modes.
        foreach ($entry in $packages.GetEnumerator()) {
            $refInner = Join-Path $WorkDir ("ref-inner-" + $entry.Key)
            New-Item -ItemType Directory -Force -Path $refInner | Out-Null
            $ex = Invoke-Process $oracle @('extract-inner', $entry.Value, $refInner, $Passcode)
            if ($ex.ExitCode -eq 0) {
                Compare-ExtractedTree $refInner $src ("reference inner extract ({0})" -f $entry.Key)
                foreach ($required in @('large.bin', 'nested\deep\structured.bin')) {
                    if (-not (Test-Path -LiteralPath (Join-Path $refInner $required))) {
                        Add-Result FAIL ("reference inner extract ({0})" -f $entry.Key) "missing $required"
                    }
                }
            }
            else {
                Add-Result FAIL ("reference inner extract ({0})" -f $entry.Key) "exit $($ex.ExitCode)"
            }
        }

        # 4b. Protected CNT entry must decrypt back to the source nptitle.dat.
        $refCnt = Join-Path $WorkDir 'ref-cnt'
        New-Item -ItemType Directory -Force -Path $refCnt | Out-Null
        $ex = Invoke-Process $oracle @('extract-cnt', $packages['plain'], $refCnt, $Passcode)
        $decrypted = Join-Path $refCnt 'nptitle.dat'
        if ($ex.ExitCode -eq 0 -and (Test-Path -LiteralPath $decrypted) -and
            (Test-SameFile $decrypted (Join-Path $src 'sce_sys\nptitle.dat'))) {
            Add-Result PASS 'reference CNT decrypt (nptitle.dat)' 'protected entry decrypts byte-identical'
        }
        else {
            Add-Result FAIL 'reference CNT decrypt (nptitle.dat)' 'decrypted bytes differ from source'
        }
    }
}

# ---------------------------------------------------------------------------- summary

Write-Host ''
Write-Host 'Summary' -ForegroundColor Cyan
$script:Results | Format-Table State, Name, Detail -AutoSize | Out-String | Write-Host

if (-not $KeepArtifacts -and (Test-Path -LiteralPath $WorkDir)) {
    Remove-Item -Recurse -Force -LiteralPath $WorkDir
}

if ($script:Failures -gt 0) {
    Write-Host ("RESULT: FAIL ({0} failing check(s))" -f $script:Failures) -ForegroundColor Red
    exit 1
}
Write-Host 'RESULT: PASS (all executed checks passed)' -ForegroundColor Green
exit 0
