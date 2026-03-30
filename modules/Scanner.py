import os
import json
import datetime
import platform
import ctypes
import winreg
import socket
import urllib.request
import concurrent.futures
import re

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "scan_complet.json")

# ── Imports optionnels ──
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    import wmi
    WMI_OK = True
except ImportError:
    WMI_OK = False


# ══════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════

def reg_lire(hive, chemin, cle):
    """Lit une valeur registre Windows directement."""
    try:
        with winreg.OpenKey(hive, chemin, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            val, _ = winreg.QueryValueEx(k, cle)
            return val
    except Exception:
        return None


def reg_lire_32(hive, chemin, cle):
    """Lit une valeur registre Windows 32-bit."""
    try:
        with winreg.OpenKey(hive, chemin, 0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as k:
            val, _ = winreg.QueryValueEx(k, cle)
            return val
    except Exception:
        return None




def lire_version_fichier(chemin):
    """
    Lit la version d'un .exe ou .dll Windows via les ressources du fichier.
    Retourne "1.2.3.4" ou None si impossible.
    """
    try:
        if not chemin or not os.path.exists(chemin):
            return None
        import ctypes
        taille = ctypes.windll.version.GetFileVersionInfoSizeW(chemin, None)
        if not taille:
            return None
        buf = ctypes.create_string_buffer(taille)
        ctypes.windll.version.GetFileVersionInfoW(chemin, None, taille, buf)
        val     = ctypes.c_void_p()
        lng     = ctypes.c_uint()
        ctypes.windll.version.VerQueryValueW(
            buf, "\\", ctypes.byref(val), ctypes.byref(lng)
        )
        info = ctypes.cast(val, ctypes.POINTER(ctypes.c_uint16 * 8)).contents
        # Indices corrects VS_FIXEDFILEINFO :
        # [5]=Major [4]=Minor [7]=Build [6]=Revision
        major = info[5]; minor = info[4]
        build = info[7]; rev   = info[6]
        v = f"{major}.{minor}.{build}.{rev}"
        return v if v != "0.0.0.0" else None
    except Exception:
        return None


def lire_version_registre(hive, chemin, cle="DisplayVersion"):
    """Lit la version depuis le registre Windows."""
    return reg_lire(hive, chemin, cle)

def est_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ══════════════════════════════════════════════
#  1. SYSTÈME & OS
# ══════════════════════════════════════════════

def collecter_systeme():

    hostname  = os.environ.get("COMPUTERNAME", socket.gethostname())
    username  = os.environ.get("USERNAME", "")
    win_ver   = platform.release()
    win_build = platform.version()
    arch      = platform.machine()

    # RAM via psutil ou ctypes
    ram_gb = 0
    if PSUTIL_OK:
        ram_gb = round(psutil.virtual_memory().total / (1024**3), 1)
    else:
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            memstat = MEMORYSTATUSEX()
            memstat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memstat))
            ram_gb = round(memstat.ullTotalPhys / (1024**3), 1)
        except Exception:
            ram_gb = 0

    # CPU cores
    cpu_cores = 0
    if PSUTIL_OK:
        cpu_cores = psutil.cpu_count(logical=False) or psutil.cpu_count()
    else:
        try:
            cpu_cores = int(os.environ.get("NUMBER_OF_PROCESSORS", 1))
        except Exception:
            cpu_cores = 1

    # Patches via registre
    patches = []
    # Patches depuis système (derniers_patches déjà collectés)
    patches = []

    # Version Windows exacte depuis registre
    win_display = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "DisplayVersion"
    )
    win_ubr = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "UBR"
    )
    win_edition = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "EditionID"
    )
    return {
        "hostname":        hostname,
        "username":        username,
        "windows_version": win_ver,
        "windows_build":   win_build,
        "windows_display": str(win_display or ""),
        "windows_ubr":     win_ubr or 0,
        "windows_edition": str(win_edition or ""),
        "architecture":    arch,
        "ram_gb":          ram_gb,
        "cpu_cores":       cpu_cores,
        "est_admin":       est_admin(),
        "nombre_patches":  len(patches),
        "derniers_patches": patches[-5:],
    }


# ══════════════════════════════════════════════
#  2. PATCHES WINDOWS
# ══════════════════════════════════════════════

def collecter_patches():

    patches_installes = []

    # Méthode 1 — Registre ComponentBased Servicing
    try:
        base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(key, i)
                    if "Package_for_KB" in name:
                        kb = name.split("Package_for_")[-1].split("~")[0]
                        if kb not in [p["id"] for p in patches_installes]:
                            patches_installes.append({"id": kb, "date": ""})
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    # Méthode 2 — Registre Hotfix
    if not patches_installes:
        try:
            base2 = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base2,
                                0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        kb = winreg.EnumKey(key, i)
                        if kb.upper().startswith("KB"):
                            patches_installes.append({"id": kb, "date": ""})
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass

    # Méthode 3 — WMI Win32_QuickFixEngineering via ctypes
    if not patches_installes:
        try:
            import subprocess
            result = subprocess.run(
                ["wmic", "qfe", "get", "HotFixID", "/format:list"],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.splitlines():
                if "HotFixID=" in line:
                    kb = line.split("=")[-1].strip()
                    if kb and kb.upper().startswith("KB"):
                        patches_installes.append({"id": kb, "date": ""})
        except Exception:
            pass

    # Windows Update service via winreg
    wu_start = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\wuauserv",
        "Start"
    )
    wu_actif = wu_start in (2, 3)

    # Auto Update config
    au_options = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
        "AUOptions"
    )
    return {
        "patches_installes":        patches_installes[:20],
        "nb_patches":               len(patches_installes),
        "windows_update_actif":     wu_actif,
        "auto_update_options":      au_options,
        "mises_a_jour_en_attente":  0,
    }


# ══════════════════════════════════════════════
#  3. SÉCURITÉ
# ══════════════════════════════════════════════

def collecter_securite():

    uac = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA"
    )

    # LSASS RunAsPPL
    lsass = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "RunAsPPL"
    )

    # WDigest
    wdigest = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "UseLogonCredential"
    )

    # NTLM Level
    ntlm = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "LmCompatibilityLevel"
    )

    # PowerShell ExecutionPolicy
    ps_policy = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
        "ExecutionPolicy"
    ) or "Restricted"

    # BitLocker via registre
    bitlocker = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\BitLocker",
        "PreventDeviceEncryption"
    )

    # Credential Guard
    cred_guard = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "EnableVirtualizationBasedSecurity"
    )

    # Secure Boot via registre
    secure_boot = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        "UEFISecureBootEnabled"
    )

    # TLS 1.0
    tls10 = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
        "Enabled"
    )

    # SSL 3.0
    ssl30 = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
        "Enabled"
    )

    # Defender via registre
    defender_rtp = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Defender",
        "DisableAntiSpyware"
    )
    defender_age = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Defender\Signature Updates",
        "SignaturesLastUpdated"
    )

    # Calculer âge signatures
    age_signatures = 9999
    if defender_age:
        try:
            import struct
            ts = struct.unpack('<Q', defender_age[:8])[0]
            EPOCH_DIFF = 11644473600
            ts_unix = (ts / 10000000) - EPOCH_DIFF
            age_signatures = int((datetime.datetime.now().timestamp() - ts_unix) / 86400)
        except Exception:
            age_signatures = 9999

    return {
        "uac_active":          uac == 1,
        "lsass_protege":       lsass == 1,
        "wdigest_active":      wdigest == 1,
        "ntlm_niveau":         ntlm if ntlm is not None else "inconnu",
        "ps_execution_policy": ps_policy,
        "bitlocker_actif":     bitlocker != 1,
        "credential_guard":    cred_guard == 1,
        "secure_boot":         secure_boot == 1,
        "tls10_active":        tls10 == 1,
        "ssl30_active":        ssl30 == 1,
        "defender": {
            "protection_temps_reel": defender_rtp != 1,
            "antivirus_actif":       defender_rtp != 1,
            "age_signatures_jours":  age_signatures,
        },
    }


# ══════════════════════════════════════════════
#  4. RÉSEAU
# ══════════════════════════════════════════════

def collecter_reseau():

    # Ports via psutil (ZERO netstat)
    ports_ouverts = []
    if PSUTIL_OK:
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == "LISTEN":
                    port = conn.laddr.port
                    if port not in ports_ouverts:
                        ports_ouverts.append(port)
            ports_ouverts.sort()
        except Exception:
            pass

    # SMBv1 via registre
    smb1 = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1"
    )
    smb1_active = smb1 == 1

    # SMB Signing
    smb_signing = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "RequireSecuritySignature"
    )

    # RDP via registre
    rdp_val = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections"
    )
    rdp_active = rdp_val == 0

    # RDP NLA
    rdp_nla = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication"
    )

    # LLMNR via registre
    llmnr = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "EnableMulticast"
    )
    llmnr_active = llmnr != 0 if llmnr is not None else True

    # NetBIOS via registre
    netbios = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
        "NodeType"
    )

    # Firewall via registre
    fw_domain = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        "EnableFirewall"
    )
    fw_private = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "EnableFirewall"
    )
    fw_public = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
        "EnableFirewall"
    )
    parefeu_desactive = any(v == 0 for v in [fw_domain, fw_private, fw_public] if v is not None)

    # Partages via registre
    partages = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Shares") as key:
            i = 0
            while True:
                try:
                    nom = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, nom) as sk:
                        try:
                            path = winreg.QueryValueEx(sk, "Path")[0]
                        except Exception:
                            path = ""
                    partages.append({"nom": nom, "chemin": path})
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    return {
        "ports_ouverts":     ports_ouverts,
        "nombre_ports":      len(ports_ouverts),
        "smb1_active":       smb1_active,
        "smb_signing":       smb_signing == 1,
        "rdp_active":        rdp_active,
        "rdp_nla":           rdp_nla == 1,
        "llmnr_active":      llmnr_active,
        "netbios_nodetype":  netbios,
        "parefeu_desactive": parefeu_desactive,
        "partages_reseau":   partages,
    }


# ══════════════════════════════════════════════
#  6. COMPTES UTILISATEURS
# ══════════════════════════════════════════════

def collecter_comptes():
    utilisateurs = []
    try:
        import win32net
        import win32netcon
        resume = 0
        while True:
            data, total, resume = win32net.NetUserEnum(
                None, 2, win32netcon.FILTER_NORMAL_ACCOUNT, resume
            )
            for u in data:
                utilisateurs.append({
                    "nom":               u["name"],
                    "actif":             not bool(u.get("flags", 0) & 0x2),
                    "mdp_expire_jamais": bool(u.get("flags", 0) & 0x10000),
                })
            if not resume:
                break
    except Exception:
        # Fallback via registre SAM
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SAM\SAM\Domains\Account\Users\Names",
                                0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        nom = winreg.EnumKey(key, i)
                        utilisateurs.append({
                            "nom":               nom,
                            "actif":             True,
                            "mdp_expire_jamais": True,
                        })
                        i += 1
                    except OSError:
                        break
        except Exception:
            # Dernier fallback — variables environnement
            utilisateurs.append({
                "nom":               os.environ.get("USERNAME", "inconnu"),
                "actif":             True,
                "mdp_expire_jamais": True,
            })

    # Administrateurs via registre
    admins = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SAM\SAM\Domains\Account\Aliases\Members\S-1-5-32\220") as key:
            pass
    except Exception:
        pass

    # SID du groupe Administrateurs via ctypes
    try:
        import win32net
        admins_data = win32net.NetLocalGroupGetMembers(None, "Administrators", 1)[0]
        admins = [a["name"] for a in admins_data]
    except Exception:
        admins = [os.environ.get("USERNAME", "")]
    return {
        "nombre_utilisateurs": len(utilisateurs),
        "utilisateurs":        utilisateurs,
        "administrateurs":     admins,
        "nombre_admins":       len(admins),
    }


# ══════════════════════════════════════════════
#  7. POLITIQUE MOTS DE PASSE
# ══════════════════════════════════════════════

def collecter_politique_mdp():
    longueur_min = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "MinimumPasswordLength"
    ) or 0

    max_age = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "MaximumPasswordAge"
    )

    min_age = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "MinimumPasswordAge"
    )

    complexite = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "PasswordComplexity"
    )

    seuil_verrou = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "LockoutBadCount"
    )
    return {
        "longueur_minimale":  longueur_min,
        "age_maximum":        str(max_age) if max_age else "inconnu",
        "age_minimum":        str(min_age) if min_age else "inconnu",
        "seuil_verrouillage": str(seuil_verrou) if seuil_verrou else "jamais",
        "complexite":         complexite == 1,
    }


# ══════════════════════════════════════════════
#  8. SERVICES WINDOWS
# ══════════════════════════════════════════════

def collecter_services():
    """
    Collecte TOUS les services Windows sans jugement.
    Retourne :
    - Tous les services actifs (Auto/Manuel)
    - Unquoted service paths
    - État Print Spooler (car détection directe registre)
    """
    services_actifs   = []
    unquoted_services = []

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services") as key:
            i = 0
            while True:
                try:
                    svc_name = winreg.EnumKey(key, i)

                    start = reg_lire(winreg.HKEY_LOCAL_MACHINE,
                                     f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
                                     "Start")
                    svc_type = reg_lire(winreg.HKEY_LOCAL_MACHINE,
                                        f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
                                        "Type")
                    img_path = reg_lire(winreg.HKEY_LOCAL_MACHINE,
                                        f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
                                        "ImagePath") or ""
                    display  = reg_lire(winreg.HKEY_LOCAL_MACHINE,
                                        f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
                                        "DisplayName") or svc_name

                    # Collecter tous les services actifs (Auto=2, Manuel=3)
                    if start in (2, 3) and svc_type in (16, 32):  # Win32OwnProcess/ShareProcess
                        # Lire version du service si chemin absolu
                        svc_version = ""
                        if img_path and img_path.startswith('"'):
                            exe = img_path.split('"')[1]
                            svc_version = lire_version_fichier(exe) or ""
                        elif img_path and img_path.lower().endswith(".exe"):
                            svc_version = lire_version_fichier(img_path) or ""
                        services_actifs.append({
                            "nom":     svc_name,
                            "display": str(display)[:80],
                            "start":   "Auto" if start == 2 else "Manuel",
                            "chemin":  img_path[:100],
                            "version": svc_version,
                        })

                    # Unquoted paths — tous types
                    if img_path and " " in img_path and not img_path.startswith('"') and \
                       not img_path.lower().startswith("c:\\windows"):
                        unquoted_services.append({
                            "service": svc_name,
                            "chemin":  img_path[:120],
                        })

                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    # Print Spooler — état direct
    spooler_start = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\Spooler",
        "Start"
    )
    spooler_actif = spooler_start in (2, 3)

    # Remote Registry — état direct
    remreg_start = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\RemoteRegistry",
        "Start"
    )
    remote_registry_actif = remreg_start in (2, 3)
    return {
        "services_actifs":       services_actifs[:30],
        "nb_services_actifs":    len(services_actifs),
        "unquoted_services":     unquoted_services[:15],
        "nb_unquoted":           len(unquoted_services),
        "spooler_actif":         spooler_actif,
        "remote_registry_actif": remote_registry_actif,
    }


# ══════════════════════════════════════════════
#  9. LOGS & ÉVÉNEMENTS
# ══════════════════════════════════════════════

def collecter_logs():

    echecs     = 0
    nouveaux   = 0
    privileges = 0
    politique  = 0
    efface     = 0

    # Lire via win32evtlog si disponible
    try:
        import win32evtlog

        def compter_events(log, event_ids, max_events=200):
            count  = 0
            try:
                handle = win32evtlog.OpenEventLog(None, log)
                flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                lu     = 0
                while lu < max_events:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events:
                        break
                    for e in events:
                        if e.EventID & 0xFFFF in event_ids:
                            count += 1
                        lu += 1
                        if lu >= max_events:
                            break
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass
            return count

        echecs     = compter_events("Security", {4625})
        nouveaux   = compter_events("Security", {4720})
        privileges = compter_events("Security", {4672})
        politique  = compter_events("Security", {4719})
        efface     = compter_events("Security", {1102})

    except Exception:
        # Pas de droits admin ou win32evtlog absent
        echecs = nouveaux = privileges = politique = efface = 0
    return {
        "echecs_connexion":       echecs,
        "nouveaux_comptes":       nouveaux,
        "utilisation_privileges": privileges,
        "changements_politique":  politique,
        "audit_efface":           efface,
    }


# ══════════════════════════════════════════════
#  PERSISTENCE & AUTORUNS
# ══════════════════════════════════════════════

def collecter_persistence():
    tous_autoruns    = []
    autorun_suspects = []

    SUSPECTS = [".vbs", ".bat", ".ps1", ".cmd", "temp\\", "tmp\\"]

    AUTORUN_KEYS = [
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    for hive, chemin in AUTORUN_KEYS:
        try:
            with winreg.OpenKey(hive, chemin) as key:
                i = 0
                while True:
                    try:
                        nom, valeur, _ = winreg.EnumValue(key, i)
                        suspect = any(s in valeur.lower() for s in SUSPECTS)
                        entry   = {"nom": nom, "valeur": valeur[:100], "suspect": suspect}
                        tous_autoruns.append(entry)
                        if suspect:
                            autorun_suspects.append(entry)
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass

    return {
        "tous_autoruns":    tous_autoruns,
        "autorun_suspects": autorun_suspects,
        "unquoted_services": [],
        "taches_suspectes": [],
    }

# ══════════════════════════════════════════════
#  HARDWARE — CPU, BIOS, TPM
# ══════════════════════════════════════════════

def collecter_hardware():
    hardware = {}

    # CPU via registre
    try:
        cpu_name = reg_lire(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "ProcessorNameString"
        )
        cpu_id = reg_lire(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "Identifier"
        )
        cpu_vendor = reg_lire(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "VendorIdentifier"
        )
        hardware["cpu"] = {
            "nom":    str(cpu_name or "").strip(),
            "id":     str(cpu_id or "").strip(),
            "vendor": str(cpu_vendor or "").strip(),
        }
    except Exception:
        hardware["cpu"] = {}

    # BIOS via registre
    try:
        bios_vendor = reg_lire(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\BIOS",
            "BIOSVendor"
        )
        bios_version = reg_lire(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\BIOS",
            "BIOSVersion"
        )
        bios_date = reg_lire(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\BIOS",
            "BIOSReleaseDate"
        )
        sys_manufacturer = reg_lire(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\BIOS",
            "SystemManufacturer"
        )
        sys_product = reg_lire(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\BIOS",
            "SystemProductName"
        )
        hardware["bios"] = {
            "vendor":       str(bios_vendor or "").strip(),
            "version":      str(bios_version or "").strip(),
            "date":         str(bios_date or "").strip(),
            "fabricant":    str(sys_manufacturer or "").strip(),
            "modele":       str(sys_product or "").strip(),
        }
    except Exception:
        hardware["bios"] = {}

    # TPM via registre
    try:
        tpm_version = reg_lire(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\TPM\Enum",
            "0"
        )
        tpm_actif = reg_lire(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Tpm",
            "WinPEPlatformID"
        )
        # TPM présent si clé existe
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Services\TPM") as k:
                tpm_presente = True
        except Exception:
            tpm_presente = False

        hardware["tpm"] = {
            "presente": tpm_presente,
            "version":  str(tpm_version or "").strip(),
        }
    except Exception:
        hardware["tpm"] = {"presente": False, "version": ""}

    # GPU (basique via registre)
    try:
        GPU_REG = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, GPU_REG) as key:
            gpu_desc, _ = winreg.QueryValueEx(key, "DriverDesc")
            gpu_ver, _  = winreg.QueryValueEx(key, "DriverVersion")
            # Chemin du driver GPU
            try:
                gpu_drv, _ = winreg.QueryValueEx(key, "InstalledDisplayDrivers")
                gpu_drv_path = os.path.join(
                    os.environ.get("SystemRoot","C:\\Windows"),
                    "System32", str(gpu_drv).split(",")[0].strip()
                )
                ver_fichier = lire_version_fichier(gpu_drv_path)
            except Exception:
                ver_fichier = None
            hardware["gpu"] = {
                "nom":            str(gpu_desc or "").strip(),
                "version":        str(gpu_ver or "").strip(),
                "version_driver": ver_fichier or str(gpu_ver or "").strip(),
            }
    except Exception:
        hardware["gpu"] = {}

    return hardware


# ══════════════════════════════════════════════
#  BIBLIOTHÈQUES — .NET, OpenSSL, DLL sensibles
# ══════════════════════════════════════════════

def collecter_bibliotheques():
    libs = {}

    # Versions .NET installées via registre
    dotnet_versions = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\NET Framework Setup\NDP") as key:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, sub) as sk:
                        try:
                            ver, _ = winreg.QueryValueEx(sk, "Version")
                            sp, _  = winreg.QueryValueEx(sk, "SP")
                            dotnet_versions.append({
                                "version": str(ver),
                                "sp":      int(sp) if sp else 0,
                                "cle":     sub,
                            })
                        except Exception:
                            pass
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    # .NET Core/5+ via registre
    try:
        base = r"SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedhost"
        ver_core = reg_lire(winreg.HKEY_LOCAL_MACHINE, base, "Version")
        if ver_core:
            dotnet_versions.append({"version": str(ver_core), "type": "dotnet_core"})
    except Exception:
        pass

    libs["dotnet"] = dotnet_versions

    # OpenSSL — chercher dans dossiers communs
    openssl_ver = None
    OPENSSL_PATHS = [
        r"C:\Program Files\OpenSSL-Win64\bin",
        r"C:\Program Files (x86)\OpenSSL-Win32\bin",
        r"C:\OpenSSL\bin",
        r"C:\Program Files\Git\usr\bin",
        r"C:\xampp\apache\bin",
    ]
    for path in OPENSSL_PATHS:
        dll_path = os.path.join(path, "libssl-3-x64.dll")
        dll_path2 = os.path.join(path, "libssl-1_1-x64.dll")
        for dll, ver_nom in [(dll_path, "3"), (dll_path2, "1.1")]:
            if os.path.exists(dll):
                try:
                    info = os.stat(dll)
                    # Version depuis nom du fichier (plus fiable pour OpenSSL)
                    # libssl-3-x64.dll → OpenSSL 3.x
                    # libssl-1_1-x64.dll → OpenSSL 1.1.x
                    # Chercher version dans openssl.exe ou openssl.cnf
                    version = None
                    openssl_exe = os.path.join(path, "openssl.exe")
                    if os.path.exists(openssl_exe):
                        version = lire_version_fichier(openssl_exe)
                    # Si version bizarre (>100) → utiliser version du nom
                    if not version or (version and float(version.split(".")[0]) > 10):
                        version = ver_nom  # "3" ou "1.1"
                    openssl_ver = {
                        "chemin":  dll,
                        "taille":  info.st_size,
                        "version": version or ver_nom
                    }
                except Exception:
                    openssl_ver = {"chemin": dll, "taille": 0, "version": ver_nom}
                break

    libs["openssl"] = openssl_ver

    # DLL sensibles Windows — versions
    DLL_SENSIBLES = {
        "ntdll.dll":     r"C:\Windows\System32\ntdll.dll",
        "kernel32.dll":  r"C:\Windows\System32\kernel32.dll",
        "advapi32.dll":  r"C:\Windows\System32\advapi32.dll",
        "winsock2.dll":  r"C:\Windows\System32\ws2_32.dll",
        "schannel.dll":  r"C:\Windows\System32\schannel.dll",
        "cryptsp.dll":   r"C:\Windows\System32\cryptsp.dll",
        "secur32.dll":   r"C:\Windows\System32\secur32.dll",
    }

    dlls = {}
    for nom, chemin in DLL_SENSIBLES.items():
        if os.path.exists(chemin):
            try:
                stat    = os.stat(chemin)
                version = lire_version_fichier(chemin)
                dlls[nom] = {
                    "present":      True,
                    "version":      version or "",
                    "taille_bytes": stat.st_size,
                    "modifie":      datetime.datetime.fromtimestamp(
                        stat.st_mtime).strftime("%Y-%m-%d"),
                }
            except Exception:
                dlls[nom] = {"present": True, "version": ""}
        else:
            dlls[nom] = {"present": False, "version": ""}

    libs["dlls_systeme"] = dlls

    # Visual C++ Runtime versions
    vcpp_versions = []
    try:
        VCPP_KEYS = [
            # r"SOFTWARE\\Microsoft\\VisualStudio\\",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ]
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") as key:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, sub) as sk:
                        try:
                            nom = winreg.QueryValueEx(sk, "DisplayName")[0]
                            if "Visual C++" in nom or "VC++ " in nom:
                                ver = ""
                                try:
                                    ver = winreg.QueryValueEx(sk, "DisplayVersion")[0]
                                except Exception:
                                    pass
                                vcpp_versions.append({"nom": nom, "version": ver})
                        except Exception:
                            pass
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    libs["vcpp"] = vcpp_versions

    # PowerShell version
    ps_ver = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine",
        "PowerShellVersion"
    )
    libs["powershell_version"] = str(ps_ver or "")

    return libs

# ══════════════════════════════════════════════
#  TÂCHES PLANIFIÉES
# ══════════════════════════════════════════════

def collecter_taches():
    taches_suspectes = []
    taches_toutes    = []
    try:
        TASKS_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
        TREE_PATH  = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"

        def lire_arbre(hive, chemin, prefix=""):
            noms = []
            try:
                with winreg.OpenKey(hive, chemin) as key:
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(key, i)
                            noms += lire_arbre(hive, chemin + "\\" + sub, prefix + "\\" + sub)
                            try:
                                with winreg.OpenKey(hive, chemin + "\\" + sub) as sk:
                                    winreg.QueryValueEx(sk, "Id")
                                    noms.append(prefix + "\\" + sub)
                            except Exception:
                                pass
                            i += 1
                        except OSError:
                            break
            except Exception:
                pass
            return noms

        taches_noms = lire_arbre(winreg.HKEY_LOCAL_MACHINE, TREE_PATH)

        MS_PATHS = ["\\Microsoft\\", "\\MicrosoftEdge"]
        for nom in taches_noms[:50]:
            est_ms = any(p in nom for p in MS_PATHS)
            taches_toutes.append({"nom": nom, "microsoft": est_ms})
            if not est_ms:
                taches_suspectes.append({"nom": nom})

    except Exception:
        pass

    return {
        "nb_total":          len(taches_toutes),
        "nb_non_microsoft":  len(taches_suspectes),
        "taches_suspectes":  taches_suspectes[:15],
    }

# ══════════════════════════════════════════════
#  REGISTRE SUSPECT
# ══════════════════════════════════════════════

def collecter_registre_suspect():
    alertes = []

    # AppInit_DLLs — injection DLL au démarrage
    appinit = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "AppInit_DLLs"
    )
    if appinit and appinit.strip():
        alertes.append({"cle": "AppInit_DLLs", "valeur": str(appinit)[:100], "risque": "CRITIQUE"})

    appinit_enabled = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "LoadAppInit_DLLs"
    )
    if appinit_enabled == 1:
        alertes.append({"cle": "LoadAppInit_DLLs", "valeur": "1", "risque": "CRITIQUE"})

    # Image File Execution Options — debugger hijacking
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options") as key:
            i = 0
            while True:
                try:
                    nom = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, nom) as sk:
                        try:
                            dbg, _ = winreg.QueryValueEx(sk, "Debugger")
                            if dbg:
                                alertes.append({
                                    "cle":    f"IFEO\\{nom}",
                                    "valeur": str(dbg)[:80],
                                    "risque": "CRITIQUE"
                                })
                        except Exception:
                            pass
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    # Winlogon Userinit & Shell
    userinit = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Userinit"
    )
    shell = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Shell"
    )
    if userinit and "userinit.exe," not in userinit.lower():
        alertes.append({"cle": "Winlogon\\Userinit", "valeur": str(userinit)[:80], "risque": "CRITIQUE"})
    if shell and shell.lower() not in ("explorer.exe", ""):
        alertes.append({"cle": "Winlogon\\Shell", "valeur": str(shell)[:80], "risque": "CRITIQUE"})

    # LSA Authentication Packages
    auth_pkgs = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "Authentication Packages"
    )
    if auth_pkgs:
        pkgs = auth_pkgs if isinstance(auth_pkgs, list) else [auth_pkgs]
        for pkg in pkgs:
            if pkg and pkg.lower() not in ("msv1_0", ""):
                alertes.append({"cle": "LSA\\AuthPackages", "valeur": str(pkg)[:80], "risque": "ELEVE"})

    return {
        "nb_alertes": len(alertes),
        "alertes":    alertes,
    }


# ══════════════════════════════════════════════
#  ANTIVIRUS TIERS
# ══════════════════════════════════════════════

def collecter_antivirus():
    antivirus = []

    AV_KEYS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    # Détecter antivirus via Windows Security Center (WMI)
    # Plus fiable que liste hardcodée
    AV_WSC_KEY = r"SOFTWARE\Microsoft\Security Center\Provider\Av"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AV_WSC_KEY) as key:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, sub) as sk:
                        try:
                            nom = winreg.QueryValueEx(sk, "DisplayName")[0]
                            etat = winreg.QueryValueEx(sk, "ProductState")[0]
                            antivirus.append({
                                "nom":    str(nom),
                                "etat":   int(etat),
                                "actif":  int(etat) in (266240, 266256, 397568),
                            })
                        except Exception:
                            pass
                    i += 1
                except OSError:
                    break
    except Exception:
        # Fallback : chercher dans Uninstall sans liste hardcodée
        for chemin in AV_KEYS:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, chemin) as key:
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, sub) as sk:
                                try:
                                    nom = winreg.QueryValueEx(sk, "DisplayName")[0]
                                    cats = ""
                                    try:
                                        cats = str(winreg.QueryValueEx(sk, "DisplayName")[0]).lower()
                                    except Exception:
                                        pass
                                    # Détecter via publisher ou category
                                    try:
                                        pub = winreg.QueryValueEx(sk, "Publisher")[0].lower()
                                    except Exception:
                                        pub = ""
                                    ver = ""
                                    try:
                                        ver = winreg.QueryValueEx(sk, "DisplayVersion")[0]
                                    except Exception:
                                        pass
                                    # Heuristique : nom contient "security" ou "antivirus" ou "protect"
                                    if any(k in cats for k in ["security", "antivirus", "protect", "defend", "safe", "guard"]):
                                        antivirus.append({"nom": nom, "version": ver, "actif": None})
                                except Exception:
                                    pass
                            i += 1
                        except OSError:
                            break
            except Exception:
                pass

    # Windows Security Center via registre
    wsc_av = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Security Center",
        "AntiVirusDisableNotify"
    )
    return {
        "antivirus_detectes":  antivirus,
        "nb_antivirus":        len(antivirus),
        "defender_uniquement": len(antivirus) == 0,
        "notifications_desactivees": wsc_av == 1,
    }
# ══════════════════════════════════════════════
#  PROCESSUS SUSPECTS
# ══════════════════════════════════════════════

def collecter_processus():
    processus_suspects = []
    connexions_suspectes = []

    if PSUTIL_OK:
        try:
            for proc in psutil.process_iter(["name", "exe", "pid", "username"]):
                try:
                    nom = (proc.info.get("name") or "")
                    exe = (proc.info.get("exe") or "").lower()

                    # Seulement processus exécutés depuis dossiers suspects
                    DOSSIERS_SUSPECTS = [
                        "\\temp\\", "\\tmp\\",
                        "\\appdata\\local\\temp\\",
                        "\\appdata\\roaming\\",
                        "\\downloads\\",
                        "\\public\\",
                    ]
                    if exe and any(d in exe for d in DOSSIERS_SUSPECTS):
                        processus_suspects.append({
                            "pid":    proc.info.get("pid"),
                            "nom":    nom,
                            "exe":    proc.info.get("exe", ""),
                            "raison": "exécuté depuis dossier non standard"
                        })
                except Exception:
                    pass
        except Exception:
            pass

        # Connexions réseau vers ports non standard
        try:
            PORTS_SUSPECTS = [4444, 1337, 31337, 8888, 9999, 6666, 1234, 12345, 4545, 7777]
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED" and conn.raddr:
                    ip_remote = conn.raddr.ip
                    port_remote = conn.raddr.port
                    if port_remote in PORTS_SUSPECTS and not ip_remote.startswith("127."):
                        connexions_suspectes.append({
                            "local":  f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote": f"{ip_remote}:{port_remote}",
                            "pid":    conn.pid,
                        })
        except Exception:
            pass

    return {
        "nb_suspects":         len(processus_suspects),
        "processus_suspects":  processus_suspects[:10],
        "connexions_suspectes": connexions_suspectes,
    }
# ══════════════════════════════════════════════
#  WIFI & SÉCURITÉ RÉSEAU SANS FIL
# ══════════════════════════════════════════════

def collecter_wifi():
    profils_wifi   = []
    profils_faibles = []

    try:
        WIFI_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WIFI_PATH) as key:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, sub) as sk:
                        try:
                            ssid = winreg.QueryValueEx(sk, "ProfileName")[0]
                            profils_wifi.append({"ssid": ssid})
                        except Exception:
                            pass
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    # Profils WiFi via fichiers XML
    wifi_dir = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"),
                             "Microsoft", "Wlansvc", "Profiles", "Interfaces")
    try:
        for root, dirs, files in os.walk(wifi_dir):
            for f in files:
                if f.endswith(".xml"):
                    try:
                        path = os.path.join(root, f)
                        with open(path, "r", encoding="utf-8", errors="ignore") as fp:
                            content = fp.read()
                            # Chercher SSID et type auth
                            import re as _re
                            ssid_match = _re.search(r"<name>(.+?)</name>", content)
                            auth_match = _re.search(r"<authentication>(.+?)</authentication>", content)
                            if ssid_match:
                                ssid = ssid_match.group(1)
                                auth = auth_match.group(1) if auth_match else "inconnu"
                                profil = {"ssid": ssid, "auth": auth}
                                if auth.lower() in ("open", "wep"):
                                    profils_faibles.append(profil)
                                if not any(p.get("ssid") == ssid for p in profils_wifi):
                                    profils_wifi.append(profil)
                    except Exception:
                        pass
    except Exception:
        pass

    # Dédupliquer par SSID
    vus_ssid = set()
    profils_uniques  = []
    faibles_uniques  = []
    for p in profils_wifi:
        ssid = p.get("ssid", "")
        if ssid not in vus_ssid:
            vus_ssid.add(ssid)
            profils_uniques.append(p)
    for p in profils_faibles:
        ssid = p.get("ssid", "")
        if ssid in vus_ssid:
            faibles_uniques.append(p)

    return {
        "nb_profils":      len(profils_uniques),
        "profils_wifi":    profils_uniques[:10],
        "profils_faibles": faibles_uniques,
    }


# ══════════════════════════════════════════════
#  DNS & PROXY
# ══════════════════════════════════════════════

def collecter_dns_proxy():
    dns_serveurs  = []
    proxy_config  = {}

    # DNS via registre
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces") as key:
            i = 0
            while True:
                try:
                    iface = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, iface) as sk:
                        for val in ("NameServer", "DhcpNameServer"):
                            try:
                                dns, _ = winreg.QueryValueEx(sk, val)
                                if dns and dns.strip():
                                    for d in dns.split(","):
                                        d = d.strip()
                                        if d and d not in dns_serveurs:
                                            dns_serveurs.append(d)
                            except Exception:
                                pass
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    # DNS over HTTPS
    doh = reg_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "EnableAutoDoh"
    )

    # Proxy via registre
    proxy_enable = reg_lire(
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyEnable"
    )
    proxy_server = reg_lire(
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyServer"
    )
    proxy_override = reg_lire(
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyOverride"
    )
    dns_separés = []
    for d in dns_serveurs:
        for ip in d.replace(",", " ").split():
            ip = ip.strip()
            if ip and re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                if ip not in dns_separés:
                    dns_separés.append(ip)
    dns_serveurs = dns_separés

    # DNS suspects (pas Google/Cloudflare/OpenDNS/locaux)
    DNS_CONNUS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                  "9.9.9.9", "208.67.222.222", "208.67.220.220",
                  "4.4.4.4", "64.6.64.6", "0.0.0.0"]
    dns_suspects = [d for d in dns_serveurs
                    if d not in DNS_CONNUS
                    and not d.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3"))]

    return {
        "dns_serveurs":    dns_serveurs,
        "dns_suspects":    dns_suspects,
        "doh_actif":       doh == 2,
        "proxy_actif":     proxy_enable == 1,
        "proxy_serveur":   proxy_server or "",
        "proxy_override":  proxy_override or "",
    }


# ══════════════════════════════════════════════
#  CERTIFICATS
# ══════════════════════════════════════════════

def collecter_certificats():
    certs_suspects = []
    certs_expires  = []

    try:
        import ssl
        import datetime as dt

        # Lire le magasin de certificats Windows
        stores = ["ROOT", "CA", "MY"]
        maintenant = dt.datetime.utcnow()

        for store_name in stores:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    f"SOFTWARE\\Microsoft\\SystemCertificates\\{store_name}\\Certificates") as store:
                    i = 0
                    while True:
                        try:
                            thumb = winreg.EnumKey(store, i)
                            with winreg.OpenKey(store, thumb) as cert_key:
                                try:
                                    blob, _ = winreg.QueryValueEx(cert_key, "Blob")
                                    # Chercher "CN=" dans le blob
                                    try:
                                        blob_str = blob.decode("latin-1", errors="ignore")
                                        import re as _re
                                        cn_match = _re.search(r"[A-Za-z0-9 \.\-]{5,50}", blob_str)
                                    except Exception:
                                        pass
                                except Exception:
                                    pass
                            i += 1
                        except OSError:
                            break
            except Exception:
                pass

    except Exception:
        pass

    # Compter via registre
    nb_root = 0
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates") as key:
            i = 0
            while True:
                try:
                    winreg.EnumKey(key, i)
                    nb_root += 1
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    nb_ca = 0
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\SystemCertificates\CA\Certificates") as key:
            i = 0
            while True:
                try:
                    winreg.EnumKey(key, i)
                    nb_ca += 1
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    return {
        "nb_root_ca":      nb_root,
        "nb_ca":           nb_ca,
        "certs_suspects":  certs_suspects,
        "certs_expires":   certs_expires,
    }
# ══════════════════════════════════════════════
#  DRIVERS VULNÉRABLES
# ══════════════════════════════════════════════

def collecter_drivers():
    drivers_tiers    = []
    drivers_non_signes = []

    try:
        DRIVERS_PATH = r"SYSTEM\CurrentControlSet\Services"

        # Drivers connus vulnérables (liste LOLDRIVERS)
        # Collecter TOUS les drivers kernel tiers
        # ZERO liste hardcodée — collecter brut pour analyse
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, DRIVERS_PATH) as key:
            i = 0
            while True:
                try:
                    svc_name = winreg.EnumKey(key, i)
                    svc_type = reg_lire(
                        winreg.HKEY_LOCAL_MACHINE,
                        f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
                        "Type"
                    )
                    if svc_type == 1:  # Kernel driver
                        img = reg_lire(
                            winreg.HKEY_LOCAL_MACHINE,
                            f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
                            "ImagePath"
                        ) or ""
                        img_lower = img.lower()
                        # Driver hors system32/drivers = tiers
                        if img and img.strip() and \
                           "system32\\drivers" not in img_lower and \
                           "systemroot" not in img_lower and \
                           "\\windows\\" not in img_lower:
                            drivers_tiers.append({
                                "nom":    svc_name,
                                "chemin": img[:100],
                            })
                    i += 1
                except OSError:
                    break
                except OSError:
                    break
    except Exception:
        pass

    return {
        "nb_drivers_tiers":      len(drivers_tiers),
        "drivers_tiers":         drivers_tiers[:15],
        "drivers_vulnerables":   drivers_non_signes,
        "nb_vulnerables":        len(drivers_non_signes),
    }

# ══════════════════════════════════════════════
#  SCAN PRINCIPAL
# ══════════════════════════════════════════════

def lancer_scan():
    debut = datetime.datetime.now()
    scan = {
        "date_scan":       debut.isoformat(),
        "systeme":         collecter_systeme(),
        "patches":         collecter_patches(),
        "securite":        collecter_securite(),
        "reseau":          collecter_reseau(),
        "comptes":         collecter_comptes(),
        "politique_mdp":   collecter_politique_mdp(),
        "services":        collecter_services(),
        "persistence":     collecter_persistence(),
        "logs":            collecter_logs(),
        "hardware":        collecter_hardware(),
        "bibliotheques":   collecter_bibliotheques(),
        "taches":          collecter_taches(),
        "registre":        collecter_registre_suspect(),
        "antivirus":       collecter_antivirus(),
        "processus":       collecter_processus(),
        "wifi":            collecter_wifi(),
        "dns_proxy":       collecter_dns_proxy(),
        "certificats":     collecter_certificats(),
        "drivers":         collecter_drivers(),
    }

    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(scan, f, indent=2, ensure_ascii=False)

    duree = int((datetime.datetime.now() - debut).total_seconds())
    sys_i = scan.get("systeme", {})
    libs_i = scan.get("bibliotheques", {})
    hw_i   = scan.get("hardware", {})
    openssl_ver = libs_i.get("openssl", {}).get("version", "") if libs_i.get("openssl") else ""
    return scan

if __name__ == "__main__":
    lancer_scan()
    