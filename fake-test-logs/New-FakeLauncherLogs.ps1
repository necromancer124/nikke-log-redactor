<#
  Generates a FAKE but realistic infected NIKKE launcher install for testing the redactor.
  Format copied from real (clean) launcher logs; infection lines copied from public excerpts.
  All personal values are invented: user "Aiko", PC "DESKTOP-K8V3Q2L", e-mail, home IP, agent UUID.
#>
param([string] $Root = (Join-Path $PSScriptRoot 'realistic'))

$ErrorActionPreference = 'Stop'
$rnd    = New-Object System.Random 42
$user   = 'Aiko'
$pc     = 'DESKTOP-K8V3Q2L'
$agent  = '7c1e4b2a-93d0-4f6e-b8a5-2d9c0e7f1a36'
$homeIp = '192.168.0.104'
$mail   = 'aiko.player@example.com'

$base = Join-Path $Root 'NIKKE\Launcher'
$dbgDir = Join-Path $base 'intl_service'
$tgDir  = Join-Path $base 'log\tinyget'
New-Item -ItemType Directory -Force $dbgDir, $tgDir | Out-Null

$src = 'https://www.nikkelauncher.com/assets/index.vue_vue_type_script_setup_true_lang.js (18)'
$normal = @(
  "`"[js-bridge][request][call_service] [object Object]`", source: $src"
  "`"[js-bridge][request][listen_broadcast] [object Object]`", source: $src"
  "`"[js-bridge][response][Srv_Config_GetConfigs] [object Object]`", source: $src"
  "`"[js-bridge][response][Srv_LoginMgr_GetInitInfo] [object Object]`", source: $src"
  "`"[js-bridge][response][Srv_LoginMgr_QueryLastAccountInfo] [object Object]`", source: $src"
  "`"[js-bridge][response][Srv_Config_GetCfgDB] [object Object]`", source: $src"
  '"[BgVideo][Login] video canplay [object Object]", source: https://www.nikkelauncher.com/assets/login--index.js (1)'
)
function Stamp-Dbg([datetime] $t) { '[{0:MMdd}/{0:HHmmss}.{1:000}:INFO:CONSOLE' -f $t, $t.Millisecond }

$dbg = New-Object System.Collections.Generic.List[string]
$sessions = @(
  @{ T=[datetime]'2026-10-30 19:12:05'; Infect=$false },
  @{ T=[datetime]'2026-11-01 20:37:10'; Infect=$true; First=$true;  Dl='20261101-203712-789'; Pay='20261101-203814-233' },
  @{ T=[datetime]'2026-11-02 18:48:55'; Infect=$false },
  @{ T=[datetime]'2026-11-02 22:19:20'; Infect=$true; First=$false; Dl='20261102-221928-372'; Pay='20261102-221928-372' },
  @{ T=[datetime]'2026-11-03 17:02:40'; Infect=$true; First=$false; Dl='20261103-170242-785'; Pay='20261103-170319-405' }
)

foreach ($s in $sessions) {
  $t = $s.T
  # personal stuff the launcher really logs, mixed into normal lines
  $dbg.Add((Stamp-Dbg $t) + '(18)] "[js-bridge][response][Srv_Config_GetGamePath] C:\Users\' + $user + '\AppData\Roaming\nikke_launcher", source: ' + $src)
  $dbg.Add((Stamp-Dbg $t.AddMilliseconds(40)) + '(18)] "[js-bridge][response][Srv_LoginMgr_QueryLastAccountInfo] ' + $mail + '", source: ' + $src)
  for ($i = 0; $i -lt 120; $i++) {
    $t = $t.AddMilliseconds($rnd.Next(1, 90))
    $dbg.Add((Stamp-Dbg $t) + '(18)] ' + $normal[$rnd.Next(0, $normal.Count)])
    if ($i -eq 60 -and $s.Infect) {
      $t = $t.AddMilliseconds(1200)
      $dbg.Add((Stamp-Dbg $t) + '(1)] "lua downloaded to log\tinyget\tinyget.' + $s.Pay + '.log", source:  (1)')
      $dbg.Add((Stamp-Dbg $t.AddMilliseconds(121)) + '(1)] "k2f_chan registered", source:  (1)')
      $verb = if ($s.First) { 'adopted' } else { 'resuming' }
      $dbg.Add((Stamp-Dbg $t.AddMilliseconds(244)) + '(1)] "' + $verb + ' ' + $agent + '", source:  (1)')
      $dbg.Add((Stamp-Dbg $t.AddMilliseconds(258)) + '(1)] "agent started as ' + $pc + '", source:  (1)')
    }
  }
  if ($s.Infect) {
    # tinyget download log: binary header + BOM, like the real ones
    $tg = New-Object System.Collections.Generic.List[string]
    $tt = $s.T.AddSeconds(2)
    $tg.Add('log created at: ' + $tt.ToString('yyyy-MM-dd HH:mm:ss'))
    $tg.Add('LOG format: [YYYY-MM-DD hh:mm:ss.xxx][tid][LEVEL][FILE(LINE)]FUNCTION' + "`t" + 'message')
    for ($i = 0; $i -lt 60; $i++) {
      $tt = $tt.AddMilliseconds($rnd.Next(2, 200))
      $id = 1073741824 + $i
      $ts = $tt.ToString('yyyy-MM-dd HH:mm:ss.fff')
      $tg.Add("[$ts][6924][ERROR][cgi_mgr.cpp(389)]CGIMgr::AddCGITask`tAddCGITask, task_id=$id, url=https://na.fleetlogd.com/fleet.repo.game.ReportGather/Guest")
      if ($i -eq 30) {
        $tt  = $tt.AddSeconds(60)
        $ts  = $tt.ToString('yyyy-MM-dd HH:mm:ss.fff')
        $ts2 = $tt.AddSeconds(2).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $pay = $s.Pay
        $tg.Add("[$ts][5980][ERROR][tiny_downloader.cpp(103)]tiny_downloader::TinyDownloader::AddTask`tadd task, task_id=2147483648, url=https://analytics.insightjs.com/comm/assets/insight.bundle, path=C:\NIKKE\Launcher\log\tinyget\tinyget.$pay.log")
        $tg.Add("[$ts2][6584][ERROR][http_curl.cpp(144)]tiny_downloader::HttpCurl::Download`ttask=2147483648, curl perform success. url=https://analytics.insightjs.com/comm/assets/insight.bundle, remote_ip=89.127.233.127, local_ip=$homeIp")
        $tg.Add("[$ts2][6584][ERROR][tiny_downloader.cpp(211)]tiny_downloader::TinyDownloader::OnTaskResult`tcode=0, strategy=0, error_msg=, url=https://analytics.insightjs.com/comm/assets/insight.bundle, user_data=0, size=205135")
      }
    }
    # Header pattern copied from a real tinyget log (86 96 00 00 .. .. .. 6A 00 00 00 00 65 00 00 00 ...)
    $header = [byte[]](0x86,0x96,0x00,0x00,0xBD,0xC1,0xEB,0x6A,0x00,0x00,0x00,0x00,0x65,0x00,0x00,0x00) + (New-Object byte[] 136)
    $body = [System.Text.Encoding]::UTF8.GetPreamble() + [System.Text.Encoding]::UTF8.GetBytes(($tg -join "`r`n") + "`r`n")
    [System.IO.File]::WriteAllBytes((Join-Path $tgDir ('tinyget.' + $s.Dl + '.log')), [byte[]]($header + $body))
  }
}
[System.IO.File]::WriteAllLines((Join-Path $dbgDir 'debug.log'), $dbg, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Fake infected install written to $Root"
Write-Host ("debug.log: {0} lines; tinyget logs: {1}" -f $dbg.Count, (Get-ChildItem $tgDir).Count)
