# =================================================================
# SOC CHESS -- AUTONOMOUS SECURITY OPERATIONS PLATFORM LAUNCHER
# =================================================================
$Host.UI.RawUI.WindowTitle = "SOC CHESS -- Platform Launcher"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "       SOC CHESS -- AUTONOMOUS SECURITY OPERATIONS PLATFORM      " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

$RootDir = $PSScriptRoot
$FrontendDir = Join-Path $RootDir "frontend"
$VenvPy = Join-Path $RootDir ".venv\Scripts\python.exe"

# 1. Detect Python
if (Test-Path $VenvPy) {
    $PyExec = $VenvPy
    Write-Host "[+] Python Environment : .venv Virtual Environment" -ForegroundColor Green
} else {
    $PyExec = "python"
    Write-Host "[*] Python Environment : System Python" -ForegroundColor Yellow
}

# 2. Check WAMP / MySQL Port 3306
try {
    $tcp = New-Object Net.Sockets.TcpClient
    $iar = $tcp.BeginConnect("127.0.0.1", 3306, $null, $null)
    $success = $iar.AsyncWaitHandle.WaitOne(1500, $false)
    if ($success -and $tcp.Connected) {
        $tcp.EndConnect($iar)
        $tcp.Close()
        Write-Host "[+] WAMP / MySQL Database: CONNECTED (Port 3306)" -ForegroundColor Green
    } else {
        $tcp.Close()
        Write-Host "[!] NOTE: MySQL is NOT listening on port 3306." -ForegroundColor Yellow
        Write-Host "    Please ensure WampServer is running (green icon in taskbar)." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] NOTE: MySQL is NOT listening on port 3306." -ForegroundColor Yellow
    Write-Host "    Please ensure WampServer is running (green icon in taskbar)." -ForegroundColor Yellow
}

# 3. Check Node.js & npm
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "[+] Node / npm Engine   : Available" -ForegroundColor Green
} else {
    Write-Host "[!] WARNING: npm was not found in PATH." -ForegroundColor Red
}

Write-Host ""
Write-Host "[*] Launching Backend Server (FastAPI :8001)..." -ForegroundColor Cyan
Start-Process -FilePath "cmd.exe" -ArgumentList "/k title SOC_CHESS_BACKEND && `"`"$PyExec`" -m uvicorn backend.main:app --host 127.0.0.1 --port 8001 --reload --reload-dir backend`"" -WorkingDirectory $RootDir

Write-Host "[*] Launching Frontend Server (React Vite :5173)..." -ForegroundColor Cyan
Start-Process -FilePath "cmd.exe" -ArgumentList "/k title SOC_CHESS_FRONTEND && npm run dev" -WorkingDirectory $FrontendDir

Write-Host "[*] Waiting for services to initialize..." -ForegroundColor DarkGray
Start-Sleep -Seconds 4

Write-Host "[*] Opening SOC Chess Platform in default browser..." -ForegroundColor Green
Start-Process "http://localhost:5173"

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [*] SOC CHESS IS NOW ACTIVE!" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [*] Frontend UI : http://localhost:5173" -ForegroundColor White
Write-Host " [*] Backend API : http://127.0.0.1:8001/docs" -ForegroundColor White
Write-Host " [*] Splunk Web  : http://localhost:8000" -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Backend & Frontend processes are running in their own windows."
Write-Host " You can safely close this launcher window at any time."
Write-Host ""
Read-Host " Press Enter to close this launcher window"
