# SOC CHESS -- Register Wireshark Protocol
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  SOC CHESS -- REGISTERING WIRESHARK PROTOCOL      " -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

$regFile = Join-Path $PSScriptRoot "register_wireshark_protocol.reg"
$p = Start-Process -FilePath "reg.exe" -ArgumentList "import `"$regFile`"" -Wait -PassThru -NoNewWindow

if ($p.ExitCode -eq 0) {
    Write-Host "[*] Successfully registered 'socchess://' protocol for Wireshark!" -ForegroundColor Green
} else {
    Write-Host "[!] Warning: Please run this script as Administrator to register the protocol." -ForegroundColor Yellow
}
Read-Host "Press Enter to exit"
