# NIKKE log redactor

Turns your NIKKE PC launcher logs into a **privacy-safe evidence package** for the community report and law enforcement.

- **Read-only.** Your original logs are never changed, moved or deleted.
- **Offline.** Nothing is uploaded. You decide where the folder goes.
- **No install.** Uses the PowerShell that comes with Windows.

## How to use (no typing needed)

1. Download both files into the same folder: `Check-My-NIKKE-Logs.bat` and `Redact-NikkeLogs.ps1`.
   Open them in Notepad and read them first. That's the safe habit with any script during an incident.
2. **Double-click `Check-My-NIKKE-Logs.bat`.**
   - It finds NIKKE in the usual places (`C:\NIKKE`, `D:\NIKKE`, `Program Files\NIKKE`, …).
   - Not found? A window asks you to pick your NIKKE folder.
   - Saved your log somewhere else? **Drag the file or folder onto `Check-My-NIKKE-Logs.bat`.**
   - Works even while the launcher is open.
3. Watch k2f-chan dance while it works. 💃
4. Your browser opens a **side-by-side check**: your original log on the left, what you'll share on the right, with every removed value highlighted.
   This page is private and is **not** in the share folder.
5. A folder named `NIKKE-evidence-<date>` appears on your Desktop and **opens automatically**. That's the folder you share.
   The terminal, the side-by-side page and `WHAT-TO-SEND.txt` all list exactly which files to send and which to keep.
   If a file couldn't be read, you get a warning instead of a false "clean".

## Testing without a real infection

`fake-test-logs/New-FakeLauncherLogs.ps1` builds a fake infected install (made-up user, PC name, agent ID and IP) in the real launcher log format:

```
powershell -ExecutionPolicy Bypass -File .\fake-test-logs\New-FakeLauncherLogs.ps1
powershell -ExecutionPolicy Bypass -File .\Redact-NikkeLogs.ps1 -Path .\fake-test-logs\realistic\NIKKE -OutputRoot .\test-output
```

Expected: 21 incident lines, 1 agent ID, and none of the fake personal values in the output.

Advanced: `powershell -ExecutionPolicy Bypass -File .\Redact-NikkeLogs.ps1 -Path "E:\Games\NIKKE" -Country DE`
(`-NoOpen`, `-NoAnimation`, `-NoGui` are also available.)

## What's in the package

| File | What it is |
|---|---|
| `evidence.txt` | Only the incident-related log lines, with personal data removed |
| `evidence.json` | The same, plus file fingerprints, dates and counts, for investigators |
| `SHA256SUMS.txt` | Fingerprints of the two files above, so nobody can edit them unnoticed |

## What gets kept, hashed or removed

| Data | What happens | Why |
|---|---|---|
| Lines about `insightjs`, `k2f_chan`, `insight.bundle`, agent start/adopt/resume | **Kept** | That's the evidence |
| Every other log line | **Dropped** | Not needed, may be personal |
| SHA-256 of each original log file | **Recorded** | Proves which original file the lines came from |
| Agent ID (the UUID the malware gave your PC) | **Hashed** → `agent:xxxxxxxxxxxxxxxx` | Can't be read back, but investigators who seize the attacker's server can hash their IDs the same way and match victims |
| PC name (`agent started as …`) | **Removed** → `<PC-NAME>` | Personal |
| Windows user name in paths | **Removed** → `<USER>` | Personal |
| Bearer tokens, passwords | **Removed** | Secrets |
| E-mail addresses | **Removed** | Personal |
| IP addresses | **Removed**, except the known attacker IPs `89.127.233.127`, `89.126.250.172` | Your IP is personal; the attacker's is evidence |

## Important

- **Keep your original logs** (and an offline copy, like a USB stick) until this is over. The package proves *which* file it came from, but the police may want the original.
- **Never send** passwords, seed phrases or ID documents to anyone, including us.
- This tool does **not** clean your PC. Use the official check guide for that: https://x.com/NIKKE_en/status/2118118928631451774
