# A2Z IDS/IPS Windows Deployment Script
# PowerShell script for Windows deployment
# Usage: .\deploy.ps1 [options]

param(
    [string]$Interface = "Ethernet",
    [string]$Mode = "passive",
    [string]$InstallDir = "C:\Program Files\A2Z-IDS",
    [string]$DataDir = "C:\ProgramData\A2Z-IDS",
    [switch]$SkipDocker,
    [switch]$SkipBuild,
    [switch]$Native,
    [string]$GrafanaPassword = "admin123",
    [string]$JwtSecret = "",
    [switch]$Help
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Colors for output
$Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Blue"
    White = "White"
}

function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Colors.Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Colors.Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Colors.Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Colors.Red
}

function Show-Usage {
    Write-Host @"
A2Z IDS/IPS Windows Deployment Script

Usage: .\deploy.ps1 [OPTIONS]

OPTIONS:
    -Interface <name>        Network interface to monitor (default: Ethernet)
    -Mode <mode>             Deployment mode: passive|inline|hybrid (default: passive)
    -InstallDir <path>       Installation directory (default: C:\Program Files\A2Z-IDS)
    -DataDir <path>          Data directory (default: C:\ProgramData\A2Z-IDS)
    -SkipDocker              Skip Docker installation
    -SkipBuild               Skip building from source
    -Native                  Install natively without Docker
    -GrafanaPassword <pwd>   Set Grafana admin password (default: admin123)
    -JwtSecret <secret>      Set JWT secret for API authentication
    -Help                    Show this help message

EXAMPLES:
    .\deploy.ps1                                    # Default installation
    .\deploy.ps1 -Interface "Wi-Fi" -Mode inline    # Monitor Wi-Fi interface in inline mode
    .\deploy.ps1 -Native -InstallDir "C:\A2Z-IDS"   # Native installation
    .\deploy.ps1 -SkipDocker -SkipBuild             # Quick setup with existing Docker

"@
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Chocolatey {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Status "Chocolatey already installed"
        return
    }
    
    Write-Status "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Write-Success "Chocolatey installed"
}

function Install-Dependencies {
    Write-Status "Installing system dependencies..."
    
    Install-Chocolatey
    
    # Install required packages
    $packages = @(
        "git",
        "curl",
        "wget",
        "7zip",
        "npcap"  # WinPcap replacement for packet capture
    )
    
    foreach ($package in $packages) {
        Write-Status "Installing $package..."
        choco install $package -y
    }
    
    Write-Success "System dependencies installed"
}

function Install-Docker {
    if ($SkipDocker) {
        Write-Status "Skipping Docker installation"
        return
    }
    
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Write-Status "Docker already installed"
        return
    }
    
    Write-Status "Installing Docker Desktop..."
    choco install docker-desktop -y
    
    Write-Warning "Please restart your computer and start Docker Desktop manually"
    Write-Success "Docker Desktop installed"
}

function Install-Rust {
    if (Get-Command rustc -ErrorAction SilentlyContinue) {
        Write-Status "Rust already installed"
        return
    }
    
    Write-Status "Installing Rust..."
    
    # Download and install Rust
    $rustupUrl = "https://win.rustup.rs/x86_64"
    $rustupPath = "$env:TEMP\rustup-init.exe"
    
    Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupPath
    Start-Process -FilePath $rustupPath -ArgumentList "-y" -Wait
    
    # Add Rust to PATH
    $env:PATH += ";$env:USERPROFILE\.cargo\bin"
    
    Write-Success "Rust installed"
}

function Install-Go {
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Status "Go already installed"
        return
    }
    
    Write-Status "Installing Go..."
    choco install golang -y
    Write-Success "Go installed"
}

function Install-NodeJS {
    if (Get-Command node -ErrorAction SilentlyContinue) {
        Write-Status "Node.js already installed"
        return
    }
    
    Write-Status "Installing Node.js..."
    choco install nodejs -y
    Write-Success "Node.js installed"
}

function New-Directories {
    Write-Status "Creating system directories..."
    
    $directories = @(
        "$DataDir\rules",
        "$DataDir\models",
        "$DataDir\pcap",
        "$DataDir\data",
        "$DataDir\logs",
        "$InstallDir\config"
    )
    
    foreach ($dir in $directories) {
        if (!(Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    Write-Success "Directories created"
}

function New-JwtSecret {
    if ([string]::IsNullOrEmpty($JwtSecret)) {
        $bytes = New-Object byte[] 32
        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
        $JwtSecret = [System.Convert]::ToHexString($bytes).ToLower()
        Write-Status "Generated JWT secret"
    }
}

function Build-Application {
    if ($SkipBuild) {
        Write-Status "Skipping build process"
        return
    }
    
    $projectDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Write-Status "Building A2Z IDS/IPS from $projectDir..."
    
    Push-Location $projectDir
    
    try {
        if (!$Native) {
            # Build with Docker Compose
            Write-Status "Building with Docker Compose..."
            docker-compose -f docker-compose.standalone.yml build
        }
        else {
            # Native build
            Write-Status "Building core engine..."
            Push-Location "core-engine"
            cargo build --release
            Copy-Item "target\release\a2z-ids.exe" "$InstallDir\bin\" -Force
            Pop-Location
            
            Write-Status "Building management API..."
            Push-Location "management-api"
            go build -o a2z-ids-api.exe
            Copy-Item "a2z-ids-api.exe" "$InstallDir\bin\" -Force
            Pop-Location
            
            Write-Status "Building web dashboard..."
            Push-Location "web-interface"
            npm install
            npm run build
            Copy-Item "dist\*" "$InstallDir\web\" -Recurse -Force
            Pop-Location
        }
        
        Write-Success "Application built successfully"
    }
    finally {
        Pop-Location
    }
}

function Set-Configuration {
    Write-Status "Configuring A2Z IDS/IPS..."
    
    $projectDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    
    # Copy configuration files
    Copy-Item "$projectDir\config\*" "$InstallDir\config\" -Recurse -Force
    
    # Create environment file
    $envContent = @"
NETWORK_INTERFACE=$Interface
DEPLOYMENT_MODE=$Mode
GRAFANA_PASSWORD=$GrafanaPassword
JWT_SECRET=$JwtSecret
"@
    $envContent | Out-File -FilePath "$projectDir\.env" -Encoding UTF8
    
    # Update configuration for selected interface
    $configPath = "$InstallDir\config\config.yaml"
    if (Test-Path $configPath) {
        (Get-Content $configPath) -replace 'interface: "eth0"', "interface: `"$Interface`"" | Set-Content $configPath
        (Get-Content $configPath) -replace 'mode: "passive"', "mode: `"$Mode`"" | Set-Content $configPath
    }
    
    Write-Success "System configured"
}

function Start-Services {
    Write-Status "Starting A2Z IDS/IPS services..."
    
    $projectDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Push-Location $projectDir
    
    try {
        if (!$Native) {
            # Start with Docker Compose
            docker-compose -f docker-compose.standalone.yml up -d
            
            Write-Status "Waiting for services to start..."
            Start-Sleep 30
            
            # Check service health
            $services = docker-compose -f docker-compose.standalone.yml ps
            if ($services -match "Up") {
                Write-Success "Services started successfully"
            }
            else {
                Write-Error "Some services failed to start"
                docker-compose -f docker-compose.standalone.yml logs
                exit 1
            }
        }
        else {
            # Install as Windows services
            Write-Status "Installing Windows services..."
            Write-Warning "Native Windows service integration not yet implemented"
            Write-Status "You can run the applications manually from $InstallDir\bin\"
        }
    }
    finally {
        Pop-Location
    }
}

function Show-AccessInfo {
    Write-Success "A2Z IDS/IPS deployment completed!"
    Write-Host ""
    Write-Host "Access Information:" -ForegroundColor White
    Write-Host "==================" -ForegroundColor White
    Write-Host "🌐 Web Dashboard:     http://localhost:3000" -ForegroundColor Green
    Write-Host "📊 Grafana:           http://localhost:3001 (admin:$GrafanaPassword)" -ForegroundColor Green
    Write-Host "🔧 API:               http://localhost:8080" -ForegroundColor Green
    Write-Host "📈 Prometheus:        http://localhost:9090" -ForegroundColor Green
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor White
    Write-Host "==============" -ForegroundColor White
    Write-Host "📁 Install Dir:       $InstallDir" -ForegroundColor Cyan
    Write-Host "📊 Data Dir:          $DataDir" -ForegroundColor Cyan
    Write-Host "🔌 Interface:         $Interface" -ForegroundColor Cyan
    Write-Host "⚙️  Mode:             $Mode" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Useful Commands:" -ForegroundColor White
    Write-Host "===============" -ForegroundColor White
    if (!$Native) {
        Write-Host "View logs:    docker-compose -f docker-compose.standalone.yml logs -f" -ForegroundColor Yellow
        Write-Host "Stop:         docker-compose -f docker-compose.standalone.yml down" -ForegroundColor Yellow
        Write-Host "Restart:      docker-compose -f docker-compose.standalone.yml restart" -ForegroundColor Yellow
    }
    else {
        Write-Host "Binaries:     $InstallDir\bin\" -ForegroundColor Yellow
        Write-Host "Config:       $InstallDir\config\" -ForegroundColor Yellow
        Write-Host "Logs:         $DataDir\logs\" -ForegroundColor Yellow
    }
    Write-Host ""
}

function Main {
    if ($Help) {
        Show-Usage
        exit 0
    }
    
    Write-Status "Starting A2Z IDS/IPS deployment on Windows..."
    
    # Check administrator privileges
    if (!$Native -and !(Test-Administrator)) {
        Write-Error "This script requires administrator privileges"
        Write-Status "Please run PowerShell as Administrator"
        exit 1
    }
    
    # Run deployment steps
    Install-Dependencies
    
    if (!$Native) {
        Install-Docker
    }
    else {
        Install-Rust
        Install-Go
        Install-NodeJS
        New-Directories
    }
    
    New-JwtSecret
    Set-Configuration
    Build-Application
    Start-Services
    Show-AccessInfo
    
    Write-Success "Deployment completed successfully!"
}

# Run main function
Main 