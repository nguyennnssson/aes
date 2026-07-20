<#
.SYNOPSIS
    Flash AES firmware to ESP32-CAM-MB and attach monitor without triggering bootloader mode.

.DESCRIPTION
    The CH340G auto-program circuit asserts DTR/RTS when a serial port opens, which
    pulls GPIO0 LOW and resets the chip into bootloader mode. This script separates
    the flash and monitor steps so the monitor always uses --no-reset.

.PARAMETER Port
    COM port the ESP32-CAM-MB is connected to. Default: COM3

.PARAMETER MonitorOnly
    Skip flashing — attach monitor to an already-running device only.

.PARAMETER FlashOnly
    Flash firmware but do not open the monitor afterward.

.EXAMPLE
    .\flash.ps1
    .\flash.ps1 -Port COM5
    .\flash.ps1 -Port COM3 -MonitorOnly
    .\flash.ps1 -Port COM3 -FlashOnly
#>

param(
    [string]$Port = "COM3",
    [switch]$MonitorOnly,
    [switch]$FlashOnly
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== AES ESP32-CAM Flash/Monitor Helper ===" -ForegroundColor Cyan
Write-Host "Port: $Port" -ForegroundColor Gray
Write-Host ""

if (-not $MonitorOnly) {
    Write-Host "[1/2] Flashing firmware..." -ForegroundColor Yellow
    Write-Host "      (CH340G auto-program circuit will hold GPIO0 LOW + pulse EN)" -ForegroundColor Gray
    Write-Host ""

    idf.py -p $Port flash
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Flash failed (exit code $LASTEXITCODE)." -ForegroundColor Red
        Write-Host "  - Check Device Manager for the correct COM port number." -ForegroundColor Red
        Write-Host "  - Make sure no other serial app (PuTTY, Arduino IDE) has the port open." -ForegroundColor Red
        Write-Host "  - Try a different USB cable (must support data, not charge-only)." -ForegroundColor Red
        exit 1
    }

    Write-Host ""
    Write-Host "Flash complete. ESP32 is now running the new firmware." -ForegroundColor Green

    if ($FlashOnly) {
        Write-Host "(-FlashOnly specified — skipping monitor)" -ForegroundColor Gray
        exit 0
    }

    # Brief pause so the chip finishes booting before the monitor port-open
    Write-Host "Waiting 2s for chip to stabilise before attaching monitor..." -ForegroundColor Gray
    Start-Sleep -Seconds 2
}

Write-Host ""
Write-Host "[2/2] Attaching monitor (--no-reset: will NOT re-enter bootloader)..." -ForegroundColor Yellow
Write-Host "      Expected output: WiFi connect -> MQTT connect -> Telemetry stream" -ForegroundColor Gray
Write-Host "      Exit with Ctrl + ]" -ForegroundColor Gray
Write-Host ""

idf.py -p $Port monitor --no-reset
