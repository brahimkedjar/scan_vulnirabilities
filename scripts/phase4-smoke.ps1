[CmdletBinding()]
param(
    [ValidateSet("Downloaded", "Installed", "Auto")]
    [string]$Runtime = "Downloaded",

    [ValidatePattern('^1\.132\.\d+$')]
    [string]$VsCodeVersion = "1.132.0",

    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$TestElectronVersion = "3.1.0",

    [switch]$RealOsv,
    [switch]$AllowRealOsvNetwork,
    [switch]$SkipCompile,
    [switch]$KeepArtifacts,
    [string]$VsixPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($RealOsv -and -not $AllowRealOsvNetwork) {
    throw "-RealOsv requires the explicit -AllowRealOsvNetwork acknowledgement."
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Get-VsCodeVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable
    )

    try {
        $lines = & $Executable --version 2>$null
        if ($LASTEXITCODE -ne 0) {
            return $null
        }
        $versions = @($lines | Where-Object { $_ -match '^\d+\.\d+\.\d+$' })
        if ($versions.Count -eq 0) {
            return $null
        }
        return $versions[0]
    }
    catch {
        return $null
    }
}

function Find-InstalledVsCode132 {
    $candidates = [System.Collections.Generic.List[string]]::new()
    $codeCommand = Get-Command "code" -ErrorAction SilentlyContinue
    if ($null -ne $codeCommand) {
        $source = $codeCommand.Source
        if ([IO.Path]::GetExtension($source) -ieq ".exe") {
            $candidates.Add($source)
        }
        else {
            # The standard Windows installation exposes bin\code.cmd. Its
            # CLI wrapper reports the VS Code product version, while invoking
            # Code.exe directly with --version reports the embedded Node
            # runtime in recent releases. Validate the wrapper, then return
            # the adjacent Electron executable to @vscode/test-electron.
            $wrapperVersion = Get-VsCodeVersion -Executable $source
            $binParent = Split-Path -Parent $source
            if (-not [string]::IsNullOrWhiteSpace($binParent)) {
                $installParent = Split-Path -Parent $binParent
                if (-not [string]::IsNullOrWhiteSpace($installParent)) {
                    $electronPath = Join-Path $installParent "Code.exe"
                    if (
                        $null -ne $wrapperVersion -and
                        $wrapperVersion -match '^1\.132\.\d+$' -and
                        (Test-Path -LiteralPath $electronPath -PathType Leaf)
                    ) {
                        return [IO.Path]::GetFullPath($electronPath)
                    }
                }
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidates.Add((Join-Path $env:LOCALAPPDATA "Programs\Microsoft VS Code\Code.exe"))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidates.Add((Join-Path $env:ProgramFiles "Microsoft VS Code\Code.exe"))
    }

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }
        $version = Get-VsCodeVersion -Executable $candidate
        if ($null -ne $version -and $version -match '^1\.132\.\d+$') {
            return [IO.Path]::GetFullPath($candidate)
        }
    }
    return $null
}

function Assert-DisposableRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $tempPath = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $expectedLeaf = "dva4-$Token"
    $leaf = Split-Path -Leaf $fullPath
    $parent = [IO.Path]::GetFullPath((Split-Path -Parent $fullPath))
    if ($leaf -cne $expectedLeaf) {
        throw "Refusing cleanup because the disposable root name is unexpected: $fullPath"
    }
    if (-not $parent.Equals($tempPath.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing cleanup outside the operating-system temporary directory: $fullPath"
    }
    $marker = Join-Path $fullPath "phase4-smoke.marker"
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw "Refusing cleanup because the smoke marker is missing: $fullPath"
    }
    $markerValue = (Get-Content -Raw -LiteralPath $marker).Trim()
    if ($markerValue -cne $Token) {
        throw "Refusing cleanup because the smoke marker does not match: $fullPath"
    }
    $item = Get-Item -LiteralPath $fullPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing cleanup because the disposable root is a reparse point: $fullPath"
    }
    return $fullPath
}

function Remove-DisposableRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # VS Code can leave short-lived helper processes while the extension-host
    # process is exiting. Repeated exact-root removal avoids treating a file
    # that disappears mid-enumeration as a permanent cleanup failure.
    foreach ($attempt in 1..20) {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $Path)) {
            return
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Unable to remove the validated disposable Phase 5B root after 20 attempts: $Path"
}

function Get-DirectoryFingerprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $root = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $records = foreach ($item in (Get-ChildItem -LiteralPath $root -Recurse -Force | Sort-Object FullName)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to fingerprint a reparse-point fixture entry: $($item.FullName)"
        }
        $relative = $item.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
        if ($item.PSIsContainer) {
            "D`t$relative/"
        }
        else {
            $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
            "F`t$relative`t$($item.Length)`t$hash"
        }
    }
    return [string]::Join("`n", @($records))
}

function New-Phase5BRemediationFixture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path) {
        throw "Refusing to reuse a remediation fixture path: $Path"
    }
    New-Item -ItemType Directory -Path $Path | Out-Null
    $utf8 = [Text.UTF8Encoding]::new($false)
    $currentIntegrity = "sha512-$([Convert]::ToBase64String([byte[]]::new(64)))"
    $targetBytes = [byte[]]::new(64)
    foreach ($index in 0..63) {
        $targetBytes[$index] = 90
    }
    $targetIntegrity = "sha512-$([Convert]::ToBase64String($targetBytes))"
    $manifest = [ordered]@{
        name = "phase5b-disposable"
        version = "1.0.0"
        private = $true
        dependencies = [ordered]@{
            "fixture-npm" = "^1.2.3"
            "fixture-donor" = "1.0.0"
        }
    } | ConvertTo-Json -Depth 8
    $lockfile = [ordered]@{
        name = "phase5b-disposable"
        version = "1.0.0"
        lockfileVersion = 3
        requires = $true
        packages = [ordered]@{
            "" = [ordered]@{
                name = "phase5b-disposable"
                version = "1.0.0"
                dependencies = [ordered]@{
                    "fixture-npm" = "^1.2.3"
                    "fixture-donor" = "1.0.0"
                }
            }
            "node_modules/fixture-npm" = [ordered]@{
                version = "1.2.3"
                resolved = "https://registry.npmjs.org/fixture-npm/-/fixture-npm-1.2.3.tgz"
                integrity = $currentIntegrity
            }
            "node_modules/fixture-donor" = [ordered]@{
                version = "1.0.0"
                resolved = "https://registry.npmjs.org/fixture-donor/-/fixture-donor-1.0.0.tgz"
                integrity = $currentIntegrity
                dependencies = [ordered]@{
                    "fixture-npm" = "1.2.4"
                }
            }
            "node_modules/fixture-donor/node_modules/fixture-npm" = [ordered]@{
                version = "1.2.4"
                resolved = "https://registry.npmjs.org/fixture-npm/-/fixture-npm-1.2.4.tgz"
                integrity = $targetIntegrity
            }
        }
    } | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText((Join-Path $Path "package.json"), "$manifest`r`n", $utf8)
    [IO.File]::WriteAllText((Join-Path $Path "package-lock.json"), "$lockfile`r`n", $utf8)
}

function New-SingleFolderWorkspaceFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Folder
    )

    $workspace = @{
        folders = @(@{ path = $Folder })
        settings = @{}
    } | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText(
        $Path,
        $workspace,
        [Text.UTF8Encoding]::new($false)
    )
}

$scriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptPath)) {
    throw "The smoke harness must be run from its saved script file."
}
$extensionRoot = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $scriptPath) ".."))
$manifestPath = Join-Path $extensionRoot "package.json"
$fixtureSource = Join-Path $extensionRoot "test\extension-host\fixtures\workspace"
$launcherPath = Join-Path $extensionRoot "test\extension-host\launcher.cjs"
foreach ($requiredPath in @($manifestPath, $fixtureSource, $launcherPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required smoke-harness input is missing: $requiredPath"
    }
}
$resolvedVsixPath = $null
if (-not [string]::IsNullOrWhiteSpace($VsixPath)) {
    $resolvedVsixPath = [IO.Path]::GetFullPath($VsixPath)
    if (-not (Test-Path -LiteralPath $resolvedVsixPath -PathType Leaf)) {
        throw "Packaged extension is missing: $resolvedVsixPath"
    }
    if ([IO.Path]::GetExtension($resolvedVsixPath) -ine ".vsix") {
        throw "Packaged extension must be a .vsix file: $resolvedVsixPath"
    }
}

$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$extensionId = "$($manifest.publisher).$($manifest.name)"
if ($extensionId -cne "c9aeb496-ae78-660b-a56e-b4102ed5df53.dependency-vulnerability-auditor") {
    throw "Unexpected extension ID: $extensionId"
}
if ([string]$manifest.version -cne "0.7.0") {
    throw "Phase 5C smoke requires extension version 0.7.0, found $($manifest.version)."
}
$fixtureSourceFingerprint = Get-DirectoryFingerprint -Path $fixtureSource
$disposableFixtureFingerprint = $null

$token = [Guid]::NewGuid().ToString("N").Substring(0, 12)
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "dva4-$token"
$runtimePrefix = Join-Path $temporaryRoot "te"
$fixtureParent = Join-Path $temporaryRoot "fixture"
$fixtureRoot = Join-Path $fixtureParent "workspace"
$userDataDirectory = Join-Path $temporaryRoot "u"
$extensionsDirectory = Join-Path $temporaryRoot "e"
$completeUserDataDirectory = Join-Path $temporaryRoot "u-complete"
$completeExtensionsDirectory = Join-Path $temporaryRoot "e-complete"
$remediationRoot = Join-Path $temporaryRoot "remediation-preview"
$remediationUserData = Join-Path $temporaryRoot "u-remediation"
$remediationExtensions = Join-Path $temporaryRoot "e-remediation"
$vscodeCache = Join-Path $temporaryRoot "vc"
$markerPath = Join-Path $temporaryRoot "phase4-smoke.marker"
$testElectronModule = Join-Path $runtimePrefix "node_modules\@vscode\test-electron"
$workspaceFile = Join-Path $fixtureRoot "phase4.code-workspace"
$completeWorkspaceFile = Join-Path $temporaryRoot "phase5b-complete.code-workspace"
$remediationWorkspaceFile = Join-Path $temporaryRoot "phase5b-remediation-preview.code-workspace"

$environmentNames = @(
    "PHASE4_EXTENSION_ID",
    "PHASE4_EXTENSION_MODE",
    "PHASE4_EXTENSION_ROOT",
    "PHASE4_EXTENSIONS_DIR",
    "PHASE4_FIXTURE_ROOT",
    "PHASE4_OSV_MODE",
    "PHASE4_TEMP_ROOT",
    "PHASE4_TEST_ELECTRON_MODULE",
    "PHASE4_USER_DATA_DIR",
    "PHASE4_VSCODE_CACHE",
    "PHASE4_VSCODE_EXECUTABLE",
    "PHASE4_VSCODE_VERSION",
    "PHASE4_VSIX_PATH",
    "PHASE4_WORKSPACE_FILE",
    "PHASE5A_SCENARIO"
)
$savedEnvironment = @{}
foreach ($name in $environmentNames) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    [IO.File]::WriteAllText($markerPath, $token, [Text.UTF8Encoding]::new($false))
    foreach ($directory in @(
        $runtimePrefix,
        $fixtureParent,
        $userDataDirectory,
        $extensionsDirectory,
        $completeUserDataDirectory,
        $completeExtensionsDirectory,
        $remediationUserData,
        $remediationExtensions,
        $vscodeCache
    )) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    Copy-Item -LiteralPath $fixtureSource -Destination $fixtureParent -Recurse
    if (-not (Test-Path -LiteralPath $workspaceFile -PathType Leaf)) {
        throw "Disposable multi-root workspace copy was not created: $workspaceFile"
    }
    if ((Get-DirectoryFingerprint -Path $fixtureRoot) -cne $fixtureSourceFingerprint) {
        throw "Disposable fixture copy does not match the source fixture."
    }
    $completeWorkspace = @{
        folders = @(
            @{ path = (Join-Path $fixtureRoot "frontend") }
        )
        settings = @{}
    } | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText(
        $completeWorkspaceFile,
        $completeWorkspace,
        [Text.UTF8Encoding]::new($false)
    )
    New-Phase5BRemediationFixture -Path $remediationRoot
    New-SingleFolderWorkspaceFile -Path $remediationWorkspaceFile -Folder $remediationRoot
    foreach ($fixtureFile in (Get-ChildItem -LiteralPath $fixtureRoot -File -Recurse -Force)) {
        $fixtureFile.IsReadOnly = $true
    }
    (Get-Item -LiteralPath $completeWorkspaceFile -Force).IsReadOnly = $true
    (Get-Item -LiteralPath $remediationWorkspaceFile -Force).IsReadOnly = $true
    $disposableFixtureFingerprint = Get-DirectoryFingerprint -Path $fixtureRoot

    if (-not $SkipCompile) {
        Push-Location $extensionRoot
        try {
            $npmCommand = (Get-Command "npm.cmd" -ErrorAction Stop).Source
            Invoke-CheckedCommand -Executable $npmCommand -Arguments @("run", "compile") -Description "Extension compilation"
        }
        finally {
            Pop-Location
        }
    }

    $npmExecutable = (Get-Command "npm.cmd" -ErrorAction Stop).Source
    Invoke-CheckedCommand -Executable $npmExecutable -Arguments @(
        "install",
        "--prefix", $runtimePrefix,
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--package-lock=false",
        "--save=false",
        "@vscode/test-electron@$TestElectronVersion"
    ) -Description "Temporary @vscode/test-electron installation"
    if (-not (Test-Path -LiteralPath $testElectronModule -PathType Container)) {
        throw "The temporary @vscode/test-electron module was not installed."
    }

    $vscodeExecutable = $null
    if ($Runtime -eq "Installed" -or $Runtime -eq "Auto") {
        $vscodeExecutable = Find-InstalledVsCode132
        if ($Runtime -eq "Installed" -and $null -eq $vscodeExecutable) {
            throw "No installed VS Code 1.132.x executable was found. Use -Runtime Downloaded for an isolated archive."
        }
    }

    [Environment]::SetEnvironmentVariable("PHASE4_EXTENSION_ID", $extensionId, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_EXTENSION_MODE", $(if ($null -eq $resolvedVsixPath) { "development" } else { "installed" }), "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_EXTENSION_ROOT", $extensionRoot, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_EXTENSIONS_DIR", $extensionsDirectory, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_FIXTURE_ROOT", $fixtureRoot, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_OSV_MODE", $(if ($RealOsv) { "real" } else { "mock" }), "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_TEMP_ROOT", $temporaryRoot, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_TEST_ELECTRON_MODULE", $testElectronModule, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_USER_DATA_DIR", $userDataDirectory, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_VSCODE_CACHE", $vscodeCache, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_VSCODE_EXECUTABLE", $vscodeExecutable, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_VSCODE_VERSION", $VsCodeVersion, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_VSIX_PATH", $resolvedVsixPath, "Process")
    [Environment]::SetEnvironmentVariable("PHASE4_WORKSPACE_FILE", $workspaceFile, "Process")
    [Environment]::SetEnvironmentVariable("PHASE5A_SCENARIO", "partial", "Process")

    $nodeExecutable = (Get-Command "node.exe" -ErrorAction Stop).Source
    Write-Host "Running Phase 5B extension-host smoke in $([IO.Path]::GetFullPath($temporaryRoot))"
    Write-Host "OSV mode: $(if ($RealOsv) { 'real (explicit network opt-in)' } else { 'deterministic mock' })"
    Write-Host "Extension mode: $(if ($null -eq $resolvedVsixPath) { 'development' } else { 'installed VSIX' })"
    Write-Host "VS Code runtime: $(if ($null -ne $vscodeExecutable) { $vscodeExecutable } else { "downloaded $VsCodeVersion" })"
    Invoke-CheckedCommand -Executable $nodeExecutable -Arguments @($launcherPath) -Description "Phase 5B partial-coverage extension-host smoke"

    if ($null -eq $resolvedVsixPath) {
        [Environment]::SetEnvironmentVariable("PHASE4_EXTENSIONS_DIR", $completeExtensionsDirectory, "Process")
        [Environment]::SetEnvironmentVariable("PHASE4_USER_DATA_DIR", $completeUserDataDirectory, "Process")
        [Environment]::SetEnvironmentVariable("PHASE4_WORKSPACE_FILE", $completeWorkspaceFile, "Process")
        [Environment]::SetEnvironmentVariable("PHASE5A_SCENARIO", "complete", "Process")
        Write-Host "Running Phase 5B frontend-only complete-scan command scenario"
        Invoke-CheckedCommand -Executable $nodeExecutable -Arguments @($launcherPath) -Description "Phase 5B complete-coverage extension-host smoke"

        [Environment]::SetEnvironmentVariable("PHASE4_EXTENSIONS_DIR", $remediationExtensions, "Process")
        [Environment]::SetEnvironmentVariable("PHASE4_USER_DATA_DIR", $remediationUserData, "Process")
        [Environment]::SetEnvironmentVariable("PHASE4_FIXTURE_ROOT", $remediationRoot, "Process")
        [Environment]::SetEnvironmentVariable("PHASE4_WORKSPACE_FILE", $remediationWorkspaceFile, "Process")
        [Environment]::SetEnvironmentVariable("PHASE5A_SCENARIO", "remediation-preview", "Process")
        Write-Host "Running Phase 5B disposable preview-only refusal scenario"
        Invoke-CheckedCommand -Executable $nodeExecutable -Arguments @($launcherPath) -Description "Phase 5B remediation preview smoke"
    }
}
finally {
    $fixtureIntegrityFailure = $null
    try {
        if ((Test-Path -LiteralPath $fixtureSource -PathType Container) -and
            (Get-DirectoryFingerprint -Path $fixtureSource) -cne $fixtureSourceFingerprint) {
            $fixtureIntegrityFailure = "The source extension-host fixture changed during Phase 5B validation."
        }
        if ($null -ne $disposableFixtureFingerprint -and
            (Test-Path -LiteralPath $fixtureRoot -PathType Container) -and
            (Get-DirectoryFingerprint -Path $fixtureRoot) -cne $disposableFixtureFingerprint) {
            $fixtureIntegrityFailure = "The disposable extension-host fixture changed during Phase 5B validation."
        }
    }
    catch {
        $fixtureIntegrityFailure = "Could not verify source fixture integrity: $($_.Exception.Message)"
    }
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], "Process")
    }
    if ($KeepArtifacts) {
        Write-Warning "Keeping disposable Phase 5B artifacts by request: $temporaryRoot"
    }
    elseif (Test-Path -LiteralPath $temporaryRoot) {
        $validatedRoot = Assert-DisposableRoot -Path $temporaryRoot -Token $token
        Remove-DisposableRoot -Path $validatedRoot
        Write-Host "Removed validated disposable Phase 5B root: $validatedRoot"
    }
    if ($null -ne $fixtureIntegrityFailure) {
        throw $fixtureIntegrityFailure
    }
}
