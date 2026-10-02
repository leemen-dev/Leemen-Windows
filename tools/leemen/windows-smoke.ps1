param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$Screenshot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class LeemenSmokeWindow {
    [StructLayout(LayoutKind.Sequential)]
    public struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")]
    public static extern bool PrintWindow(IntPtr window, IntPtr dc, uint flags);
}
'@

$profileDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('leemen-smoke-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $profileDirectory | Out-Null
$process = $null
try {
    $process = Start-Process -FilePath (Resolve-Path -LiteralPath $Executable).Path -PassThru -ArgumentList @(
        '-workdir', ('"' + $profileDirectory + '"'), '-noupdate'
    )
    $window = [IntPtr]::Zero
    for ($attempt = 0; $attempt -lt 40; ++$attempt) {
        $process.Refresh()
        if ($process.HasExited) {
            throw "Leemen exited before showing its window: $($process.ExitCode)."
        }
        $window = $process.MainWindowHandle
        if ($window -ne [IntPtr]::Zero) { break }
        Start-Sleep -Seconds 1
    }
    if ($window -eq [IntPtr]::Zero) { throw 'Leemen did not show a main window within 40 seconds.' }
    Start-Sleep -Seconds 2
    $process.Refresh()
    if ($process.HasExited) { throw 'Leemen exited immediately after opening its window.' }
    if ($process.MainWindowTitle -notmatch 'Leemen') {
        throw "Unexpected application title: $($process.MainWindowTitle)."
    }
    $rect = [LeemenSmokeWindow+Rect]::new()
    if (-not [LeemenSmokeWindow]::GetWindowRect($window, [ref]$rect)) {
        throw 'Cannot inspect the Leemen window.'
    }
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    if ($width -lt 240 -or $height -lt 240) { throw 'The main window has an unexpected size.' }
    $bitmap = [System.Drawing.Bitmap]::new($width, $height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $dc = $graphics.GetHdc()
        try {
            if (-not [LeemenSmokeWindow]::PrintWindow($window, $dc, 2)) {
                throw 'Windows could not render the application window for inspection.'
            }
        } finally { $graphics.ReleaseHdc($dc) }
        $bitmap.Save($Screenshot, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $graphics.Dispose()
        $bitmap.Dispose()
    }
    Write-Output "Opened $($process.MainWindowTitle) with an empty profile; captured $($width)x$($height)."
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit(10000) | Out-Null
    }
    Remove-Item -LiteralPath $profileDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
