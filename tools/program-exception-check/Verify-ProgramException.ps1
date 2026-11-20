$ErrorActionPreference='Stop'
$r=Get-Content 'C:\ProgramData\RansomGuard\installation-receipt.json' -Raw|ConvertFrom-Json
& $r.paths.python -X utf8 (Join-Path $PSScriptRoot 'Verify-ProgramException.py')
