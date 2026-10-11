param(
    [switch]$SkipFrontendBuild
)

$ErrorActionPreference = "Stop"

function Write-Section($title) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Test-Port($TargetHost, $Port) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($TargetHost, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(2000, $false)
        if (-not $wait) { return $false }
        try {
            $tcp.EndConnect($connect)
            return $true
        }
        catch {
            return $false
        }
        finally {
            $tcp.Close()
        }
    }
    catch {
        return $false
    }
}

function Test-Http($Url, $TimeoutSec = 5) {
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Timeout = 1000 * $TimeoutSec
        $resp = $req.GetResponse()
        $resp.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Ensure-EnvFile {
    param(
        [string]$Root,
        [string]$EnvFile,
        [string]$ExampleFile
    )

    if (-not (Test-Path $EnvFile)) {
        if (Test-Path $ExampleFile) {
            Copy-Item $ExampleFile $EnvFile
            Write-Host "  Created .env from .env.example" -ForegroundColor Yellow
        } else {
            Write-Host "  ERROR: .env.example not found" -ForegroundColor Red
            return $false
        }
    }

    $content = Get-Content $EnvFile -Raw

    $replaceMap = @(
        @{ Pattern = "NVIDIA_API_KEY=your_nvidia_api_key_here"; Replace = "NVIDIA_API_KEY=demo_nvidia_key_replace_me" },
        @{ Pattern = "JWT_SECRET=replace_with_secure_random_key"; Replace = "JWT_SECRET=SOC_CHESS_AUTO_GENERATED_SECRET_$(Get-Random)" },
        @{ Pattern = "MYSQL_PASSWORD="; Replace = "MYSQL_PASSWORD=root" },
        @{ Pattern = "SPLUNK_USERNAME=admin"; Replace = "SPLUNK_USERNAME=admin" },
        @{ Pattern = "SPLUNK_PASSWORD=SocChess@123"; Replace = "SPLUNK_PASSWORD=SocChess@123" }
    )

    foreach ($item in $replaceMap) {
        if ($content -match [regex]::Escape($item.Pattern)) {
            $content = $content.Replace($item.Pattern, $item.Replace)
        }
    }

    $requiredPairs = @(
        "MYSQL_HOST=127.0.0.1",
        "MYSQL_PORT=3306",
        "MYSQL_DATABASE=soc_chess",
        "MYSQL_USERNAME=root",
        "BACKEND_HOST=127.0.0.1",
        "BACKEND_PORT=8001",
        "FRONTEND_PORT=5173",
        "SPLUNK_HOST=127.0.0.1",
        "SPLUNK_PORT=8089",
        "SPLUNK_WEB_URL=http://127.0.0.1:8000",
        "SPLUNK_INDEX=main",
        "DATASET_ROOT=$Root\datasets",
        "MODEL_DIR=ml/models"
    )

    foreach ($pair in $requiredPairs) {
        $key = $pair.Split("=")[0]
        if ($content -notmatch [regex]::Escape($key + "=")) {
            $content += "`n$pair"
        }
    }

    Set-Content -Path $EnvFile -Value $content -Encoding UTF8
    return $true
}

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

$overallOk = $true

Write-Section "SOC CHESS STRICT SETUP CHECK"

Write-Host "[1/10] Checking .env..." -ForegroundColor Yellow
$envFile = Join-Path $repoRoot ".env"
$exampleFile = Join-Path $repoRoot ".env.example"
if (-not (Ensure-EnvFile -Root $repoRoot -EnvFile $envFile -ExampleFile $exampleFile)) {
    $overallOk = $false
} else {
    Write-Host "  PASS: .env file exists and required defaults were inserted." -ForegroundColor Green
}

Write-Section "Python"
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
} else {
    Write-Host "  FAIL: Python not installed." -ForegroundColor Red
    $overallOk = $false
}

if ($pythonCmd) {
    try {
        $ver = & $pythonCmd --version 2>&1
        Write-Host "  PASS: Python detected -> $ver" -ForegroundColor Green
    } catch {
        Write-Host "  FAIL: Python not working correctly." -ForegroundColor Red
        $overallOk = $false
    }
}

$venvPath = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    if ($pythonCmd) {
        Write-Host "  Creating .venv..." -ForegroundColor Yellow
        & $pythonCmd -m venv $venvPath
    }
}
if (Test-Path $venvPython) {
    Write-Host "  PASS: .venv exists" -ForegroundColor Green
} else {
    Write-Host "  FAIL: .venv creation failed" -ForegroundColor Red
    $overallOk = $false
}

if (Test-Path $venvPython) {
    $mods = @("fastapi","uvicorn","pandas","numpy","sklearn","joblib","pymysql","dotenv")
    $missing = @()
    foreach ($m in $mods) {
        try {
            & $venvPython -c "import $m" | Out-Null
        } catch {
            $missing += $m
        }
    }
    if ($missing.Count -eq 0) {
        Write-Host "  PASS: required Python packages are installed" -ForegroundColor Green
    } else {
        Write-Host "  FAIL: missing Python packages: $($missing -join ', ')" -ForegroundColor Red
        $overallOk = $false
    }
}

if (Test-Path $venvPython) {
    $reqFile = Join-Path $repoRoot "backend\requirements.txt"
    if (Test-Path $reqFile) {
        Write-Host "  Installing backend requirements..." -ForegroundColor Yellow
        & $venvPython -m pip install --upgrade pip
        & $venvPython -m pip install -r $reqFile
    }
}

Write-Section "Frontend"
if (Get-Command node -ErrorAction SilentlyContinue) {
    Write-Host "  PASS: Node is installed -> $(node -v)" -ForegroundColor Green
} else {
    Write-Host "  FAIL: Node.js is missing. Install Node 18+." -ForegroundColor Red
    $overallOk = $false
}

if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "  PASS: npm is installed -> $(npm -v)" -ForegroundColor Green
} else {
    Write-Host "  FAIL: npm is missing" -ForegroundColor Red
    $overallOk = $false
}

if ((Get-Command node -ErrorAction SilentlyContinue) -and (Get-Command npm -ErrorAction SilentlyContinue)) {
    $frontendDir = Join-Path $repoRoot "frontend"
    if (Test-Path $frontendDir) {
        Push-Location $frontendDir
        if (-not (Test-Path "node_modules")) {
            Write-Host "  Installing frontend dependencies..." -ForegroundColor Yellow
            npm install
        } else {
            Write-Host "  PASS: frontend dependencies already installed" -ForegroundColor Green
        }
        if (-not $SkipFrontendBuild) {
            Write-Host "  Running frontend build check..." -ForegroundColor Yellow
            npm run build
            Write-Host "  PASS: frontend build succeeded" -ForegroundColor Green
        } else {
            Write-Host "  SKIP: frontend build skipped" -ForegroundColor DarkGray
        }
        Pop-Location
    }
}

Write-Section "Java / Spark"
if (Get-Command java -ErrorAction SilentlyContinue) {
    try {
        $javaOut = java -version 2>&1
        Write-Host "  PASS: Java detected" -ForegroundColor Green
        Write-Host "  $javaOut" -ForegroundColor DarkGray
    } catch {
        Write-Host "  FAIL: Java is installed but not working" -ForegroundColor Red
        $overallOk = $false
    }
} else {
    Write-Host "  FAIL: Java not installed. Install JDK 17 or 21." -ForegroundColor Red
    $overallOk = $false
}

Write-Section "MySQL"
if (Test-Port "127.0.0.1" 3306) {
    Write-Host "  PASS: MySQL is reachable on 127.0.0.1:3306" -ForegroundColor Green
} else {
    Write-Host "  FAIL: MySQL is not reachable on 127.0.0.1:3306" -ForegroundColor Red
    Write-Host "  Action: Start WAMP / MySQL and ensure the green icon is active." -ForegroundColor Yellow
    $overallOk = $false
}

Write-Section "Wireshark / TShark"
$wireshark = "C:\Program Files\Wireshark\Wireshark.exe"
$tshark = "C:\Program Files\Wireshark\tshark.exe"

if (Test-Path $wireshark) {
    Write-Host "  PASS: Wireshark found" -ForegroundColor Green
} else {
    Write-Host "  FAIL: Wireshark missing" -ForegroundColor Red
    $overallOk = $false
}
if (Test-Path $tshark) {
    Write-Host "  PASS: TShark found" -ForegroundColor Green
} else {
    Write-Host "  FAIL: TShark missing" -ForegroundColor Red
    $overallOk = $false
}

Write-Section "Splunk"
if (Test-Http "http://localhost:8000" 5) {
    Write-Host "  PASS: Splunk web UI is reachable" -ForegroundColor Green
} else {
    Write-Host "  FAIL: Splunk UI not reachable on http://localhost:8000" -ForegroundColor Red
    $overallOk = $false
}

if (Test-Http "https://localhost:8089" 5) {
    Write-Host "  PASS: Splunk REST API is reachable" -ForegroundColor Green
} else {
    Write-Host "  FAIL: Splunk API not reachable on https://localhost:8089" -ForegroundColor Red
    $overallOk = $false
}

Write-Section "Database schema"
$schemaFile = Join-Path $repoRoot "database\schema.sql"
if (Test-Path $schemaFile) {
    Write-Host "  PASS: schema file exists" -ForegroundColor Green
} else {
    Write-Host "  FAIL: database schema file missing" -ForegroundColor Red
    $overallOk = $false
}

Write-Section "FINAL RESULT"

if ($overallOk) {
    Write-Host "ALL REQUIRED CHECKS PASSED." -ForegroundColor Green
    Write-Host "The project is ready to start." -ForegroundColor Green
    Write-Host ""
    Write-Host "Run:" -ForegroundColor Yellow
    Write-Host "  .\start_soc_chess.bat" -ForegroundColor Cyan
} else {
    Write-Host "SETUP IS NOT COMPLETE." -ForegroundColor Red
    Write-Host "Fix the failed items above and run the script again." -ForegroundColor Yellow
}
