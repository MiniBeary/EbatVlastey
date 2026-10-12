param([string]$Dotnet='dotnet')
$ErrorActionPreference='Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'; $env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
$root=Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    & $Dotnet run --project tests/EbatVlastey.Tests -c Release
    if($LASTEXITCODE -ne 0) {throw 'Tests failed'}
    & $Dotnet publish src/EbatVlastey.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -p:DebugType=None -o artifacts/publish
    if($LASTEXITCODE -ne 0) {throw 'Publish failed'}
    Copy-Item -LiteralPath 'artifacts/publish/EbatVlastey.exe' -Destination 'artifacts/EbatVlastey-win-x64.exe' -Force
    $hash=(Get-FileHash -LiteralPath 'artifacts/EbatVlastey-win-x64.exe' -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $root 'artifacts/SHA256SUMS.txt'),$hash+'  EbatVlastey-win-x64.exe'+"`n",[Text.UTF8Encoding]::new($false))
} finally {Pop-Location}
