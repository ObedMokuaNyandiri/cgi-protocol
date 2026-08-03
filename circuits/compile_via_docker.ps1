<#
.SYNOPSIS
    Automates the EZKL Key Compilation Ceremony using an Ubuntu Docker Container.
.DESCRIPTION
    Because EZKL v23.0.5 panics on Windows due to PyO3 multi-threading limitations during setup(), 
    this script builds an Ubuntu 22.04 LTS container, executes the python compilation script natively,
    and maps the generated cryptographic keys back to the Windows host filesystem.
#>

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$ArtifactsDir = Join-Path $PSScriptRoot "ezkl_artifacts"

Write-Host "=========================================================="
Write-Host " CGI Protocol - EZKL Ubuntu Compilation Ceremony"
Write-Host "=========================================================="

# Check if Docker is running
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running."
    }
} catch {
    Write-Host "[ERROR] Docker is not installed or the Docker daemon is not running." -ForegroundColor Red
    Write-Host "Please start Docker Desktop and try again." -ForegroundColor Yellow
    exit 1
}

Write-Host "`n[1/3] Building the Ubuntu 22.04 Compilation Container..." -ForegroundColor Cyan
Set-Location $RootDir
docker build -t cgi-ezkl-compiler -f circuits/Dockerfile.ezkl_compiler .

# Ensure the local artifacts directory exists so Docker can map to it
if (-not (Test-Path $ArtifactsDir)) {
    New-Item -ItemType Directory -Path $ArtifactsDir | Out-Null
}

Write-Host "`n[2/3] Executing Compilation Script natively on Linux..." -ForegroundColor Cyan
Write-Host "(This will generate network.compiled, test.pk, and test.vk)" -ForegroundColor DarkGray

# Run the container and mount the local artifacts directory to /app/circuits/ezkl_artifacts
docker run --rm -v "${ArtifactsDir}:/app/circuits/ezkl_artifacts" cgi-ezkl-compiler

Write-Host "`n[3/3] Extraction Complete!" -ForegroundColor Green
Write-Host "The cryptographic keys have been securely deposited in: $ArtifactsDir" -ForegroundColor White
Write-Host "Run 'python tests/test_ezkl_proof.py' to verify the new physical keys." -ForegroundColor Yellow
