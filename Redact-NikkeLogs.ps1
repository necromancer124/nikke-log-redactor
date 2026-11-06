<#
.SYNOPSIS
  Makes a privacy-safe evidence package from NIKKE PC launcher logs.

.DESCRIPTION
  READ-ONLY on your original logs: nothing is changed, moved or deleted.

  1. Finds debug.log and tinyget logs (or uses -Path, or asks you to pick a folder).
  2. Records the SHA-256 of each ORIGINAL file (proves which file was used).
  3. Keeps ONLY the lines related to the incident (insightjs, k2f, insight.bundle, ...).
  4. In those lines:
       - Agent IDs (UUIDs)  -> SHA-256 fingerprint (unsalted, so investigators can match victims)
       - PC name, Windows user name, tokens, passwords, e-mails -> removed
       - IP addresses       -> removed, EXCEPT the known attacker IPs
  5. Writes evidence.json + evidence.txt + SHA256SUMS.txt into a new Desktop folder (this is what you share).
  6. Opens a side-by-side comparison page (original vs. shared) from your TEMP folder.
     That page contains your ORIGINAL lines: it is for your eyes only and is NOT in the share folder.

  Nothing is uploaded.

.EXAMPLE
  Double-click "Check-My-NIKKE-Logs.bat", or drag a log file / folder onto it.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Redact-NikkeLogs.ps1 -Path "D:\backup\debug.log" -Country DE
#>
[CmdletBinding()]
param(
  [string[]] $Path,
  [string]   $OutputRoot = [Environment]::GetFolderPath('Desktop'),
  [string]   $Country = '',
  [switch]   $NoOpen,
  [switch]   $NoAnimation,
  [switch]   $NoGui
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$ToolVersion = '1.1.0'

# ================================================================= rules
$KeepPatterns = @(
  'insightjs', 'insight\.bundle', 'k2f', 'agent started as', '\badopted\b', '\bresuming\b',
  'lua downloaded', '/comm/assets/', 'l\.js\?f=', 'platform_experience_helper',
  'E77CC89B-7401-4C04-8CED-149DB35ADD04', '89\.127\.233\.127', '89\.126\.250\.172'
)
$KeepRegex   = [regex]::new(($KeepPatterns -join '|'), 'IgnoreCase')
$KnownIocIps = @('89.127.233.127', '89.126.250.172', '0.0.0.0', '127.0.0.1')   # attacker IPs + non-personal block/loopback addresses
$PublicClsid = 'E77CC89B-7401-4C04-8CED-149DB35ADD04'

# Each rule: regex that matches ONLY the sensitive value, and how to replace it.
$Rules = @(
  @{ Name='Agent ID';  Rx='\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'; Kind='agent' }
  @{ Name='PC name';   Rx='(?i)(?<=agent started as\s+"?)[^\s",)]+';                    Kind='fixed'; Tag='<PC-NAME>' }
  @{ Name='User name'; Rx='(?i)(?<=[A-Z]:\\Users\\)[^\\/"\s]+';                          Kind='fixed'; Tag='<USER>' }
  @{ Name='User name'; Rx='(?i)(?<=/(?:Users|home)/)[^/"\s]+';                           Kind='fixed'; Tag='<USER>' }
  @{ Name='Token';     Rx='(?i)(?<=Bearer\s+)[A-Za-z0-9\-\._~\+/=]+';                     Kind='fixed'; Tag='<TOKEN>' }
  @{ Name='Password';  Rx='(?i)(?<=(?:agent_pass|password|passwd|token|secret)"?\s*[:=]\s*"?)[^",\s}]+'; Kind='fixed'; Tag='<REMOVED>' }
  @{ Name='E-mail';    Rx='[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}';               Kind='fixed'; Tag='<EMAIL>' }
  @{ Name='IP address';Rx='\b(?:\d{1,3}\.){3}\d{1,3}\b';                                  Kind='ip' }
)
foreach ($r in $Rules) { $r.Re = [regex]::new($r.Rx) }

# Markers used only for the comparison page (never appear in real logs)
$M1 = [char]0x27E6; $M2 = [char]0x27E7

function Get-Sha256Hex([string] $text) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) -join '') }
  finally { $sha.Dispose() }
}

# SHA-256 of a file opened read-only WITH sharing, so it works while the launcher has the log open.
function Get-FileSha256Shared([string] $file) {
  $fs = [System.IO.File]::Open($file, 'Open', 'Read', 'ReadWrite, Delete')
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { return (($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join '') }
  finally { $sha.Dispose(); $fs.Dispose() }
}

$AgentIds  = @{}
$Removed   = @{}   # what kind of data was removed, and how often

# Mode: 'share' = redacted text, 'orig' = original with sensitive values marked, 'mark' = redacted with tags marked
function Convert-Line([string] $line, [string] $mode) {
  $l = $line
  foreach ($r in $Rules) {
    $l = $r.Re.Replace($l, [System.Text.RegularExpressions.MatchEvaluator] {
      param($m)
      $v = $m.Value
      $tag = $null
      switch ($r.Kind) {
        'agent' { if ($v -ieq $PublicClsid) { return $v }
                  $fp = 'agent:' + (Get-Sha256Hex $v.ToLowerInvariant()).Substring(0, 16)
                  if ($mode -eq 'share') { $script:AgentIds[$fp] = $true }
                  $tag = "<$fp>" }
        'ip'    { if ($KnownIocIps -contains $v) { return $v }; $tag = '<IP>' }
        default { $tag = $r.Tag }
      }
      if ($mode -eq 'share') { $script:Removed[$r.Name] = 1 + [int]($script:Removed[$r.Name]) ; return $tag }
      if ($mode -eq 'orig')  { return "$M1$v$M2" }
      return "$M1$tag$M2"
    })
  }
  return $l
}

# ================================================================= k2f-chan (easter egg)
$K2F = @(
  @('  \    ,----,      ', '   \ ~( ^  ^ )~    ', '    \_\  ww /__    ', '        /  \       ', '       /____\      ', '        |  |       ', '       _|  |_      '),
  @('       ,----,    / ', '     ~( ^  ^ )~ /  ', '     __\ ww  /_/   ', '        /  \       ', '       /____\      ', '        |  |       ', '       _|  |_      '),
  @('  \    ,----,    / ', '   \ ~( >  < )~ /  ', '    \_\  ww  /_/   ', '        /  \       ', '       /____\      ', '        |  \       ', '       _|   \_     '),
  @('  \    ,----,    / ', '   \ ~( ^  o )~ /  ', '    \_\  ww  /_/   ', '        /  \       ', '       /____\      ', '        /  |       ', '      _/   |_      ')
)
$K2FLines = @(
  'k2f-chan is scrubbing your secrets...',
  'k2f-chan says: hash the agent IDs, hide the PC name!',
  'k2f-chan says: the attacker IP stays. it is evidence.',
  'k2f-chan says: change passwords from ANOTHER device!'
)
function Show-K2F([int] $files) {
  if ($NoAnimation -or [Console]::IsOutputRedirected) { Write-Host 'k2f-chan is scrubbing your secrets... done.'; return }
  try {
    $h = $K2F[0].Count + 3
    for ($i = 0; $i -lt $h; $i++) { Write-Host '' }
    $top = [Console]::CursorTop - $h
    $ticks = 28
    for ($t = 0; $t -le $ticks; $t++) {
      [Console]::SetCursorPosition(0, $top)
      $frame = $K2F[$t % $K2F.Count]
      foreach ($row in $frame) { Write-Host ('    ' + $row) -ForegroundColor Magenta }
      $pct = [int](100 * $t / $ticks)
      $bar = ('#' * [int]($pct / 5)).PadRight(20, '.')
      Write-Host ''
      Write-Host ('    [' + $bar + '] ' + $pct.ToString().PadLeft(3) + '%  ' + $files + ' file(s)   ') -ForegroundColor Cyan
      Write-Host ('    ' + $K2FLines[[int]($t / 8) % $K2FLines.Count].PadRight(60)) -ForegroundColor Yellow
      Start-Sleep -Milliseconds 110
    }
  } catch { Write-Host 'k2f-chan is scrubbing your secrets... done.' }
}

# ================================================================= find logs
# Fast: look in the known launcher locations first (the game folder is many GB).
# Only if nothing is there, search the folder, skipping the big game data folders.
function Find-LogsInFolder([string] $folder) {
  $hits = @()
  foreach ($base in @($folder, (Join-Path $folder 'Launcher'), (Split-Path $folder -Parent))) {
    if (-not $base) { continue }
    foreach ($rel in 'Launcher\intl_service\debug.log', 'intl_service\debug.log', 'debug.log') {
      $f = Join-Path $base $rel
      if (Test-Path -LiteralPath $f -PathType Leaf) { $hits += (Resolve-Path -LiteralPath $f).Path }
    }
    foreach ($rel in 'Launcher\log\tinyget', 'log\tinyget', 'tinyget') {
      $d = Join-Path $base $rel
      if (Test-Path -LiteralPath $d -PathType Container) { $hits += @(Get-ChildItem -LiteralPath $d -Filter 'tinyget*.log' -File | ForEach-Object { $_.FullName }) }
    }
    if ($hits.Count) { break }
  }
  if (-not $hits.Count) {
    $skip = '\\(NIKKE\\NIKKE|Unity|sail_files|\.tiny_cache|StreamingAssets|Data)\\'
    $hits = @(Get-ChildItem -LiteralPath $folder -Recurse -File -Filter '*.log' -Depth 6 -ErrorAction SilentlyContinue |
              Where-Object { $_.FullName -notmatch $skip -and ($_.Name -eq 'debug.log' -or $_.Name -like 'tinyget*.log') } |
              ForEach-Object { $_.FullName })
  }
  return @($hits | Select-Object -Unique)
}

if ($Path) {
  # "powershell -File x.ps1 -Path a,b" passes "a,b" as ONE string: split it back.
  $Path = @($Path | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().Trim('"').Trim("'") } | Where-Object { $_ })
  $expanded = @()
  foreach ($p in $Path) {
    if (Test-Path -LiteralPath $p -PathType Container) {
      $expanded += @(Find-LogsInFolder $p)
    } else { $expanded += $p }
  }
  $Path = $expanded
}

if (-not $Path -or $Path.Count -eq 0) {
  $found = @()
  foreach ($d in [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady }) {
    foreach ($sub in 'NIKKE', 'Program Files\NIKKE', 'Program Files (x86)\NIKKE') {
      $r = Join-Path $d.RootDirectory.FullName $sub
      $dbg = Join-Path $r 'Launcher\intl_service\debug.log'
      if (Test-Path -LiteralPath $dbg) { $found += $dbg }
      $tg = Join-Path $r 'Launcher\log\tinyget'
      if (Test-Path -LiteralPath $tg) { $found += @(Get-ChildItem -LiteralPath $tg -Filter 'tinyget*.log' -File | ForEach-Object { $_.FullName }) }
    }
  }
  $Path = $found
}

if ((-not $Path -or $Path.Count -eq 0) -and -not $NoGui) {
  try {
    Add-Type -AssemblyName System.Windows.Forms
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'NIKKE not found automatically. Pick your NIKKE folder (or the folder with your saved debug.log).'
    if ($dlg.ShowDialog() -eq 'OK') {
      $Path = @(Find-LogsInFolder $dlg.SelectedPath)
    }
  } catch { }
}

if (-not $Path -or $Path.Count -eq 0) {
  Write-Host 'No NIKKE launcher logs found. Drag your debug.log (or NIKKE folder) onto Check-My-NIKKE-Logs.bat.' -ForegroundColor Yellow
  exit 2
}

# ================================================================= process (read-only)
$stamp  = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$outDir = Join-Path $OutputRoot "NIKKE-evidence-$stamp"
$files  = @()
$pairs  = @()     # for the comparison page
$allKept = New-Object System.Collections.Generic.List[string]

Write-Host ''
Write-Host '  NIKKE log redactor  -  your original logs are only READ, never changed' -ForegroundColor White
Write-Host ''

foreach ($p in $Path) {
  if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { Write-Warning "Skipped (not found): $p"; continue }
  $item = Get-Item -LiteralPath $p
  $origHash = Get-FileSha256Shared $p
  $kept = New-Object System.Collections.Generic.List[string]
  $filePairs = @()
  $total = 0
  $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite, Delete')   # shared read: works while the launcher has it open
  try {
    # Always UTF-8, never guess from the first bytes: tinyget logs start with a binary header
    # that can look like a UTF-16 byte-order mark and would turn the whole file into garbage.
    $sr = New-Object System.IO.StreamReader($fs, (New-Object System.Text.UTF8Encoding($false)), $false)
    while ($null -ne ($line = $sr.ReadLine())) {
      $total++
      $line = $line.Replace([string][char]0, '').Replace([string][char]0xFEFF, '')   # drop header NULs / mid-file BOM
      if ($KeepRegex.IsMatch($line)) {
        $kept.Add((Convert-Line $line 'share'))
        $filePairs += ,@((Convert-Line $line 'orig'), (Convert-Line $line 'mark'))
      }
    }
  } finally { $fs.Dispose() }

  $safeName = Convert-Line $item.Name 'share'
  # A big file that comes out as 1-2 "lines" was not read as text: never call it clean.
  $unreadable = ($total -le 2 -and $item.Length -gt 2048)
  $files += [ordered]@{
    unreadable            = $unreadable
    file                  = $safeName
    location_type         = $(if ($p -match '(?i)intl_service\\debug\.log$') { 'launcher debug.log' } elseif ($p -match '(?i)tinyget') { 'tinyget download log' } else { 'other' })
    original_sha256       = $origHash
    original_size         = $item.Length
    original_modified_utc = $item.LastWriteTimeUtc.ToString('o')
    lines_total           = $total
    lines_kept            = $kept.Count
    lines                 = $kept.ToArray()
  }
  $pairs += [pscustomobject]@{ Name = $safeName; Hash = $origHash; Total = $total; Pairs = $filePairs; Unreadable = $unreadable; OrigPath = $item.FullName }
  $allKept.Add("===== $safeName  (sha256 $origHash, $($kept.Count)/$total lines kept) =====")
  foreach ($k in $kept) { $allKept.Add($k) }
  $allKept.Add('')
}

if ($files.Count -eq 0) {
  Write-Host 'None of the given log files could be found. Check the path and try again.' -ForegroundColor Yellow
  exit 2
}

Show-K2F $files.Count

New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$outDir = (Resolve-Path -LiteralPath $outDir).Path
$hits = ($files | ForEach-Object { $_.lines_kept } | Measure-Object -Sum).Sum
$evidence = [ordered]@{
  tool               = "Redact-NikkeLogs.ps1 $ToolVersion"
  created_utc        = (Get-Date).ToUniversalTime().ToString('o')
  country            = $Country
  windows_version    = [Environment]::OSVersion.VersionString
  indicators_found   = ($hits -gt 0)
  agent_fingerprints = @($AgentIds.Keys)
  fingerprint_method = 'agent:<first 16 hex of SHA-256(lower-case UUID)>, unsalted so investigators can match'
  removed            = $Removed
  files              = $files
}
$jsonPath = Join-Path $outDir 'evidence.json'
$txtPath  = Join-Path $outDir 'evidence.txt'
$evidence | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
if ($allKept.Count -eq 0) { $allKept.Add('(no lines)') }
$allKept  | Set-Content -LiteralPath $txtPath -Encoding UTF8
$notePath = Join-Path $outDir 'WHAT-TO-SEND.txt'
@(
  'NIKKE log check - what to send'
  '=============================='
  ''
  'SEND these files (this whole folder is safe to share):'
  '  [OK] evidence.txt      - the incident lines, personal data removed'
  '  [OK] evidence.json     - the same, for investigators'
  '  [OK] SHA256SUMS.txt    - fingerprints, so nobody can edit the files unnoticed'
  '  [OK] WHAT-TO-SEND.txt  - this note'
  ''
  'DO NOT SEND:'
  '  [X] Your original log files (debug.log, tinyget*.log). They contain your PC name,'
  '      user name and more. Keep them, plus a copy on a USB stick, in case police ask.'
  '  [X] The side-by-side page NIKKE-compare-*.html in your TEMP folder. It shows your original lines.'
  '  [X] Passwords, seed phrases or ID documents. Nobody legit will ever ask for them.'
) | Set-Content -LiteralPath $notePath -Encoding UTF8
$sums = foreach ($f in @($jsonPath, $txtPath, $notePath)) { '{0}  {1}' -f (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant(), (Split-Path $f -Leaf) }
$sums | Set-Content -LiteralPath (Join-Path $outDir 'SHA256SUMS.txt') -Encoding ASCII
$shareFiles = @('evidence.txt', 'evidence.json', 'SHA256SUMS.txt', 'WHAT-TO-SEND.txt')
$cmpPath    = Join-Path ([System.IO.Path]::GetTempPath()) "NIKKE-compare-$stamp.html"
$badFiles   = @($pairs | Where-Object { $_.Unreadable })

# ================================================================= comparison page (private, in TEMP)
function ConvertTo-HtmlMarked([string] $s, [string] $cls) {
  $e = [System.Net.WebUtility]::HtmlEncode($s)
  $e = $e.Replace([string]$M1, "<mark class=`"$cls`">").Replace([string]$M2, '</mark>')
  return $e
}
$rows = New-Object System.Text.StringBuilder
foreach ($f in $pairs) {
  [void]$rows.Append("<h2>$([System.Net.WebUtility]::HtmlEncode($f.Name))</h2><p class=meta>$($f.Pairs.Count) of $($f.Total) lines are about the incident and will be shared. The other $($f.Total - $f.Pairs.Count) lines stay on your PC. Original file fingerprint: <code>$($f.Hash)</code></p>")
  if ($f.Unreadable) { [void]$rows.Append('<p class=unread>&#9888; This file could not be read properly, so it was NOT checked. Do not assume it is clean. Keep the original and ask for help.</p>'); continue }
  if ($f.Pairs.Count -eq 0) { [void]$rows.Append('<p class=clean>Nothing about the incident in this file.</p>'); continue }
  [void]$rows.Append('<table><thead><tr><th>Your original log (stays on your PC)</th><th>What you will share</th></tr></thead><tbody>')
  foreach ($pr in $f.Pairs) {
    [void]$rows.Append('<tr><td>' + (ConvertTo-HtmlMarked $pr[0] 'old') + '</td><td>' + (ConvertTo-HtmlMarked $pr[1] 'new') + '</td></tr>')
  }
  [void]$rows.Append('</tbody></table>')
}
$removedList = if ($Removed.Count) { ($Removed.Keys | Sort-Object | ForEach-Object { "<li><b>$_</b> &times; $($Removed[$_])</li>" }) -join '' } else { '<li>Nothing personal was found in the incident lines.</li>' }
$enc = { param($s) [System.Net.WebUtility]::HtmlEncode($s) }
$what = @{ 'evidence.txt'='the incident lines, personal data removed'; 'evidence.json'='the same, for investigators'; 'SHA256SUMS.txt'='fingerprints, so nobody can edit the files unnoticed'; 'WHAT-TO-SEND.txt'='this list, as a text file' }
$sendList = (($shareFiles | ForEach-Object { "<li><span class=ok>&#10003;</span> <b>$_</b> <span class=why>$($what[$_])</span></li>" }) -join '') +
            "<li class=where>In this folder: <code>$(& $enc $outDir)</code></li>"
$keepList = (($pairs | ForEach-Object { "<li><span class=no>&#10007;</span> <b>$(& $enc (Split-Path $_.OrigPath -Leaf))</b> <span class=why>your original log: has your PC name, user name and more<br><code>$(& $enc (Split-Path $_.OrigPath -Parent))</code></span></li>" }) -join '') +
            "<li><span class=no>&#10007;</span> <b>$(& $enc (Split-Path $cmpPath -Leaf))</b> <span class=why>this page: shows your original lines<br><code>$(& $enc (Split-Path $cmpPath -Parent))</code></span></li>" +
            "<li><span class=no>&#10007;</span> Passwords, seed phrases or ID documents <span class=why>nobody legit will ever ask</span></li>"
$sendPanel = @"
<div class="send">
 <div class="col yes"><h3>&#10003; Send these 4 files</h3><p class=sub>The whole evidence folder is safe to share.</p><ul>$sendList</ul></div>
 <div class="col nope"><h3>&#10007; Do NOT send these</h3><p class=sub>Keep the originals (and a USB copy) in case police ask for them.</p><ul>$keepList</ul></div>
</div>
"@
$unreadNote = if ($badFiles.Count) { "<div class='verdict unreadbox'><b>&#9888; $($badFiles.Count) file(s) could not be read</b> and were not checked: $(($badFiles | ForEach-Object { & $enc $_.Name }) -join ', '). Do not treat them as clean.</div>" } else { '' }
$verdict = if ($hits -gt 0) { "<div class='verdict bad'><b>Incident traces found.</b> $hits line(s) mention the attack. Please submit the evidence folder.</div>" } else { "<div class='verdict good'><b>No incident traces found</b> in these logs. If you were infected before a reinstall, your old logs may be gone.</div>" }

$html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>NIKKE log check: compare</title>
<style>
body{margin:0;background:#f6f3ec;color:#111314;font:16px/1.5 "Segoe UI",system-ui,sans-serif}
header{background:#111314;color:#ebd3a2;padding:28px 40px}
header h1{margin:0;font:700 34px/1.1 Bahnschrift,"Segoe UI",sans-serif;letter-spacing:.01em}
header p{margin:8px 0 0;color:#cdbb92}
main{padding:24px 40px 60px;max-width:1400px}
.verdict{padding:14px 18px;border-radius:10px;margin:0 0 18px}
.bad{background:#fbe3d6;border:1px solid #d96629}.good{background:#e3f0e6;border:1px solid #3b7a4a}
.box{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:8px}
.card{background:#fff;border:1px solid #e1d8c6;border-radius:10px;padding:14px 18px}
.card h3{margin:0 0 6px;font-size:16px}.card ul{margin:0;padding-left:20px}
h2{margin:32px 0 4px;font-size:20px}.meta{margin:0 0 10px;color:#5b5446;font-size:14px}
table{width:100%;border-collapse:collapse;table-layout:fixed;background:#fff;border:1px solid #e1d8c6;border-radius:10px;overflow:hidden}
th{background:#111314;color:#ebd3a2;text-align:left;padding:10px 12px;font-size:14px}
td{padding:9px 12px;border-top:1px solid #eee6d6;font:13px/1.5 Consolas,"Cascadia Mono",monospace;word-break:break-all;vertical-align:top}
td+td,th+th{border-left:1px solid #e1d8c6}
mark.old{background:#fbd5d0;color:#8a1c12;padding:0 2px;border-radius:3px}
mark.new{background:#d4ecd9;color:#1d5a2c;padding:0 2px;border-radius:3px}
.clean{color:#3b7a4a}code{font-size:12px}
.warn{margin-top:28px;padding:14px 18px;background:#111314;color:#ebd3a2;border-radius:10px}
.send{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:0 0 16px}
.col{border-radius:10px;padding:16px 20px;background:#fff}
.col h3{margin:0;font-size:19px}.col .sub{margin:4px 0 10px;color:#5b5446;font-size:14px}
.col ul{list-style:none;margin:0;padding:0}.col li{padding:7px 0;border-top:1px solid #eee6d6;font-size:14px;word-break:break-all}
.col b{font-size:16px}.col code{font-size:12px;color:#5b5446}.why{display:block;color:#5b5446;font-size:13px;margin-left:22px}
.where{color:#5b5446;font-size:13px}
.yes{border:2px solid #3b7a4a}.yes h3,.ok{color:#2d6a3c}
.nope{border:2px solid #a62c37}.nope h3,.no{color:#a62c37}
.ok,.no{font-weight:700;margin-right:6px}
.unread{color:#8a4b00;background:#fff3dc;border:1px solid #e0a43a;padding:10px 14px;border-radius:8px}
.unreadbox{background:#fff3dc;border:1px solid #e0a43a}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:0 0 16px}
.step{display:flex;gap:12px;align-items:flex-start;background:#fff;border:1px solid #e1d8c6;border-radius:10px;padding:14px 16px;font-size:15px}
.step .n{flex:none;width:30px;height:30px;border-radius:50%;background:#111314;color:#ebd3a2;display:flex;align-items:center;justify-content:center;font-weight:700}
kbd{font:600 12px Consolas,monospace;background:#f1ece2;border:1px solid #cfc4ad;border-radius:4px;padding:1px 5px}
</style></head><body>
<header><h1>Your NIKKE log check</h1><p>Left: your original log. Right: the version in your evidence folder. This page is private and is NOT in the folder you share.</p></header>
<main>
$verdict
$unreadNote
<div class="steps">
 <div class="step"><span class="n">1</span><div><b>Read this page.</b> Check the right-hand column: that's everything that will be shared.</div></div>
 <div class="step"><span class="n">2</span><div><b>Your evidence folder is already open</b> in a File Explorer window behind this page. Switch to it with <kbd>Alt</kbd>+<kbd>Tab</kbd> (or click it on the taskbar).</div></div>
 <div class="step"><span class="n">3</span><div><b>Send the 4 files</b> from that folder through the official community channel. Keep everything in the red box private.</div></div>
</div>
$sendPanel
<div class="box">
 <div class="card"><h3>Removed or hashed</h3><ul>$removedList</ul></div>
 <div class="card"><h3>Where is it?</h3><p style="margin:0">Evidence folder: <code>$(& $enc $outDir)</code></p><p style="margin:6px 0 0;color:#5b5446;font-size:14px">Open it, check <code>evidence.txt</code>, then send the 4 files.</p></div>
</div>
$($rows.ToString())
<div class="warn"><b>Never send passwords, seed phrases or ID documents.</b> Keep your original logs (and a copy on a USB stick) until this is over.</div>
</main></body></html>
"@
Set-Content -LiteralPath $cmpPath -Value $html -Encoding UTF8

# ================================================================= done
Write-Host ''
Write-Host ("  Files checked: {0}   Incident lines: {1}   Agent IDs: {2}" -f $files.Count, $hits, $AgentIds.Count)
if ($hits -gt 0) { Write-Host '  Incident traces FOUND. Please send the evidence folder.' -ForegroundColor Red }
else             { Write-Host '  No incident traces found in these logs.' -ForegroundColor Yellow }
foreach ($b in $badFiles) { Write-Host "  WARNING: could not read $($b.Name) - it was NOT checked. Do not treat it as clean." -ForegroundColor Yellow }

Write-Host ''
Write-Host '  SEND these files (safe to share):' -ForegroundColor Green
foreach ($s in $shareFiles) { Write-Host ('    [OK] ' + (Join-Path $outDir $s)) -ForegroundColor Green }

Write-Host ''
Write-Host '  DO NOT SEND these (keep them private):' -ForegroundColor Red
foreach ($pr in $pairs) { Write-Host ('    [X]  ' + $pr.OrigPath + '   (original log)') -ForegroundColor Red }
Write-Host ('    [X]  ' + $cmpPath + '   (side-by-side page, opening now)') -ForegroundColor Red
Write-Host '    [X]  Passwords, seed phrases or ID documents' -ForegroundColor Red

Write-Host ''
Write-Host '  Your original logs were NOT changed. Keep them and a USB copy until this is over.'
if (-not $NoOpen) {
  # Folder first, then (after it has appeared) the page, so the page lands on top and the folder waits behind it.
  try { Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$outDir`""; Start-Sleep -Milliseconds 1500 } catch { }
  try { Start-Process $cmpPath } catch { }
  Write-Host '  Opened: your evidence folder (to send) and the side-by-side page (private).'
}
