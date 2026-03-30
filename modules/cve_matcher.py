
import sqlite3
import json
import os
import re
import datetime

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH     = os.path.join(BASE_DIR, "data", "nvd_db", "index.db")
CPE_DB      = os.path.join(BASE_DIR, "data", "nvd_db", "cpe_map.db")
SCAN_PATH   = os.path.join(BASE_DIR, "data", "scan_complet.json")
RESULT_PATH = os.path.join(BASE_DIR, "data", "cve_results.json")


# ══════════════════════════════════════════════
#  CPE MAP
# ══════════════════════════════════════════════

def ouvrir_cpe_map():
    if os.path.exists(CPE_DB):
        return sqlite3.connect(CPE_DB)
    return None


def trouver_cpe(mots_cles, conn_cpe):
    if not conn_cpe or not mots_cles:
        return None
    c = conn_cpe.cursor()
    recherche = mots_cles.lower().strip()

    c.execute("SELECT vendor, product FROM cpe_titles WHERE title=? LIMIT 1", (recherche,))
    row = c.fetchone()
    if row:
        return f"{row[0]}:{row[1]}"

    mots = [m for m in recherche.split() if len(m) >= 3]
    for longueur in range(min(3, len(mots)), 0, -1):
        for i in range(len(mots) - longueur + 1):
            fragment = " ".join(mots[i:i+longueur])
            c.execute("SELECT vendor, product FROM cpe_titles WHERE title=? LIMIT 5", (fragment,))
            rows = c.fetchall()
            if rows:
                best_score = -1
                best_cpe   = None
                for vendor, product in rows:
                    score = 0
                    if vendor == product:  score += 8
                    for mot in mots:
                        if mot in vendor:  score += 5
                        if mot in product: score += 5
                    if score > best_score:
                        best_score = score
                        best_cpe   = f"{vendor}:{product}"
                if best_cpe:
                    return best_cpe
    return None


# ══════════════════════════════════════════════
#  NORMALISATION VERSION
#  Fix : 25.0.1.0 → 25.0.1 (supprimer .0 final)
# ══════════════════════════════════════════════

def normaliser_version(v):
    """
    Normalise une version pour meilleur matching NVD.
    25.0.1.0 → 25.0.1
    10.0.26100 → 10.0.26100
    """
    if not v:
        return v
    v = str(v).strip()
    # Supprimer les .0 trailing (ex: 25.0.1.0 → 25.0.1)
    while v.endswith(".0") and v.count(".") > 1:
        v = v[:-2]
    return v


# ══════════════════════════════════════════════
#  COMPARAISON VERSIONS
# ══════════════════════════════════════════════

def extraire_parties(v):
    if not v: return None
    v = str(v).strip()
    if v.lower() in ("n/a", "*", "-", "any", "none", ""): return None
    p = re.findall(r'\d+', v)
    return [int(x) for x in p] if p else None

def comparer_versions(v1, v2):
    p1 = extraire_parties(v1)
    p2 = extraire_parties(v2)
    if p1 is None or p2 is None: return None
    for i in range(min(len(p1), len(p2))):
        if p1[i] < p2[i]: return -1
        if p1[i] > p2[i]: return +1
    if len(p1) < len(p2): return -1
    if len(p1) > len(p2): return +1
    return 0

def est_vulnerable(version, ver_debut, ver_fin, ver_fin_type):
    if not ver_debut and not ver_fin:     return True
    if not extraire_parties(version):     return True
    if ver_debut:
        c = comparer_versions(version, ver_debut)
        if c is None: return True
        if c < 0:     return False
    if ver_fin:
        c = comparer_versions(version, ver_fin)
        if c is None: return True
        if ver_fin_type == "excluding" and c >= 0: return False
        if ver_fin_type == "including" and c > 0:  return False
    return True


# ══════════════════════════════════════════════
#  RECHERCHE CVE
# ══════════════════════════════════════════════

def chercher_cve(cpe, version, conn, limite=10, version_requise=False):
    if not cpe:
        return []

    # Normaliser la version avant recherche
    version = normaliser_version(version)

    c = conn.cursor()
    c.execute("""
        SELECT cve_id, ver_debut, ver_fin, ver_fin_type
        FROM cpe_cve
        WHERE cpe_produit = ? OR cpe_produit LIKE ?
        LIMIT 2000
    """, (cpe, cpe + ":%"))
    lignes = c.fetchall()

    if not lignes:
        return []

    resultats = []
    for cve_id, vd, vf, vft in lignes:
        version_verifiee = not (vd is None and vf is None)
        if version_requise and not version_verifiee:
            continue
        if not est_vulnerable(version, vd, vf, vft):
            continue

        m = re.match(r'CVE-(\d{4})-', cve_id)
        if m and int(m.group(1)) < 2018:
            continue

        c.execute("SELECT cve_id, score, niveau, description FROM cve WHERE cve_id=?", (cve_id,))
        row = c.fetchone()
        if not row: continue

        score = row[1]
        if score is not None and float(score) < 4.0: continue

        resultats.append({
            "cve_id":           row[0],
            "score":            score,
            "niveau":           row[2],
            "description":      row[3] or "",
            "cpe":              cpe,
            "version_verifiee": version_verifiee,
        })

    resultats.sort(key=lambda x: float(x["score"] or 0), reverse=True)
    return resultats[:limite]


# ══════════════════════════════════════════════
#  MATCHING PRINCIPAL
# ══════════════════════════════════════════════

def lancer_matching():
    if not os.path.exists(DB_PATH):
        return None
    if not os.path.exists(SCAN_PATH):
        return None

    with open(SCAN_PATH, "r", encoding="utf-8") as f:
        scan = json.load(f)

    conn     = sqlite3.connect(DB_PATH)
    conn_cpe = ouvrir_cpe_map()

    # ── Déduplication globale : 1 seule CVE par ID ──
    cve_vus = set()

    if conn_cpe:
        c = conn_cpe.cursor()
        c.execute("SELECT COUNT(*) FROM cpe_titles")

    systeme     = scan.get("systeme", {})
    securite    = scan.get("securite", {})
    reseau      = scan.get("reseau", {})
    services    = scan.get("services", {})
    patches     = scan.get("patches", {})
    comptes     = scan.get("comptes", {})
    politique   = scan.get("politique_mdp", {})
    logs        = scan.get("logs", {})
    registre    = scan.get("registre", {})
    ports_ext   = scan.get("ports_externes", {})
    drivers     = scan.get("drivers", {})
    wifi        = scan.get("wifi", {})
    dns_proxy   = scan.get("dns_proxy", {})
    processus   = scan.get("processus", {})
    persistence = scan.get("persistence", {})
    hardware    = scan.get("hardware", {})
    bibliotheques = scan.get("bibliotheques", {})

    win_ver   = systeme.get("windows_version", "11")
    win_build = systeme.get("windows_build", "")

    # KBs installés — pour éviter les CVE déjà patchées
    kbs_installes = set()
    for p in patches.get("patches_installes", []):
        kb = str(p.get("id", "")).upper()
        if kb:
            kbs_installes.add(kb)
    # Aussi depuis derniers_patches systeme
    for p in systeme.get("derniers_patches", []):
        kb = str(p).upper()
        m = re.search(r'KB\d+', kb)
        if m:
            kbs_installes.add(m.group(0))

    resultats = {
        "date_analyse":   datetime.datetime.now().isoformat(),
        "systeme":        systeme,
        "categories":     [],
        "risques_config": [],
        "resume": {
            "cve_uniques":        0,
            "critique":           0,
            "eleve":              0,
            "moyen":              0,
            "risques_config":     0,
            "risques_critique":   0,
            "risques_eleve":      0,
        }
    }

    def ajouter_cve(titre, mots_cle, version=None, contexte="",
                    limite=10, version_requise=False):
        """
        Cherche CVE via cpe_map.db → NVD.
        DÉDUPLICATION GLOBALE : chaque CVE ID ajouté 1 seule fois.
        """
        cpe  = trouver_cpe(mots_cle, conn_cpe)
        if not cpe:
            return
        cves = chercher_cve(cpe, version, conn, limite * 3, version_requise)
        if not cves:
            return

        # Dédupliquer globalement
        nouvelles = []
        for c in cves:
            if c["cve_id"] not in cve_vus:
                cve_vus.add(c["cve_id"])
                nouvelles.append(c)
            if len(nouvelles) >= limite:
                break

        if nouvelles:
            resultats["categories"].append({
                "titre":    titre,
                "cpe":      cpe,
                "contexte": contexte,
                "cves":     nouvelles,
                "nb_cves":  len(nouvelles),
            })

    def ajouter_risque(niveau, titre, detail=""):
        resultats["risques_config"].append({
            "niveau": niveau,
            "titre":  titre,
            "detail": detail,
        })

    # ══════════════════════════════════════════
    # [1] OS WINDOWS
    # ══════════════════════════════════════════
    ajouter_cve(
        f"Windows {win_ver} (build {win_build})",
        f"windows {win_ver}", win_build,
        f"Build {win_build}", limite=15, version_requise=True
    )

    # Mapping port → CPE correct pour Windows
    # Port 53 sur Windows → microsoft:dns_server (pas isc:bind)
    PORT_CPE_WINDOWS = {
        21:    "vsftpd:vsftpd",
        22:    "openssh:openssh",
        25:    "postfix:postfix",
        53:    "microsoft:dns_server",   
        80:    "apache:http_server",
        110:   "dovecot:dovecot",
        135:   "microsoft:windows",
        139:   "microsoft:windows",
        143:   "dovecot:dovecot",
        443:   "openssl:openssl",
        445:   "microsoft:windows",
        1433:  "microsoft:sql_server",
        3306:  "oracle:mysql",
        3389:  "microsoft:remote_desktop_protocol",
        5432:  "postgresql:postgresql",
        5900:  "realvnc:vnc",
        5985:  "microsoft:windows_remote_management",
        8080:  "apache:tomcat",
        8443:  "apache:tomcat",
        27017: "mongodb:mongodb",
    }

    for p in ports_ext.get("ports_exposes", []):
        port    = p.get("port")
        service = p.get("service", "")

        # 1. CPE fixe depuis table PORT_CPE_WINDOWS
        cpe = PORT_CPE_WINDOWS.get(port)

        # 2. Port inconnu → chercher via nom du service
        if not cpe and service:
            cpe = trouver_cpe(service.lower(), conn_cpe)

        # 3. Toujours pas → ignorer
        if not cpe:
            continue

        # Chercher CVE
        cves = chercher_cve(cpe, None, conn, 8, True)
        nouvelles = [c for c in cves if c["cve_id"] not in cve_vus]
        for c in nouvelles[:8]:
            cve_vus.add(c["cve_id"])
        if nouvelles[:8]:
            resultats["categories"].append({
                "titre":    f"Port {port} ({service}) exposé internet",
                "cpe":      cpe,
                "contexte": f"Port {port} accessible depuis internet",
                "cves":     nouvelles[:8],
                "nb_cves":  len(nouvelles[:8]),
            })
    # ══════════════════════════════════════════
    # [3] PROTOCOLES
    # ══════════════════════════════════════════
    if reseau.get("smb1_active") is True:
        ajouter_cve("SMBv1 actif", f"windows {win_ver}", win_build,
                    "EternalBlue/WannaCry", 8, False)
        ajouter_risque("CRITIQUE", "SMBv1 activé",
                       "Désactiver : Set-SmbServerConfiguration -EnableSMB1Protocol $false")
 
    if reseau.get("rdp_active") is True:
        ajouter_cve("RDP actif", "remote desktop protocol", win_build,
                    "BlueKeep", 8, False)
        if not reseau.get("rdp_nla"):
            ajouter_risque("CRITIQUE", "RDP sans NLA", "Activer NLA")
        else:
            ajouter_risque("ELEVE", "RDP actif avec NLA", "Restreindre l'accès")

    if reseau.get("llmnr_active") is True:
        ajouter_cve("LLMNR actif", f"windows {win_ver}", win_build,
                    "LLMNR Poisoning", 5, False)
        ajouter_risque("ELEVE", "LLMNR activé",
                       "Désactiver via GPO : DNS Client → Turn off Multicast")

    if reseau.get("smb_signing") is False:
        ajouter_risque("ELEVE", "SMB Signing désactivé",
                       "Activer RequireSecuritySignature")

    if reseau.get("parefeu_desactive") is True:
        ajouter_cve("Pare-feu désactivé", f"windows {win_ver}", win_build,
                    "Aucun filtrage réseau", 5, False)
        ajouter_risque("CRITIQUE", "Pare-feu Windows désactivé",
                       "Activer les profils Domain/Private/Public")

    if securite.get("tls10_active") is True:
        ajouter_cve("TLS 1.0 actif", "openssl", None, "POODLE/BEAST", 5, True)
        ajouter_risque("ELEVE", "TLS 1.0 activé", "Désactiver dans SCHANNEL")

    if securite.get("ssl30_active") is True:
        ajouter_cve("SSL 3.0 actif", "openssl", None, "POODLE", 5, True)

    ntlm = securite.get("ntlm_niveau")
    if ntlm is not None and isinstance(ntlm, int) and ntlm < 3:
        ajouter_cve(f"NTLMv1 niveau {ntlm}", f"windows {win_ver}", win_build,
                    "Pass-the-Hash", 5, False)
        ajouter_risque("CRITIQUE", f"NTLMv1 actif (niveau {ntlm})",
                       "LmCompatibilityLevel=5")

    # Ports locaux dangereux
    for port in [5985, 5986]:
        if port in reseau.get("ports_ouverts", []):
            ajouter_cve(f"WinRM (port {port})", "windows remote management",
                        win_build, f"Port {port} actif", 5, False)

    # ══════════════════════════════════════════
    # [4] SERVICES
    # ══════════════════════════════════════════
    if services.get("spooler_actif") is True:
        ajouter_cve("Print Spooler actif", f"windows {win_ver}", win_build,
                    "PrintNightmare CVE-2021-34527", 8, False)
        ajouter_risque("CRITIQUE", "Print Spooler actif",
                       "Stop-Service Spooler; Set-Service Spooler -StartupType Disabled")
    if services.get("remote_registry_actif") is True:
        ajouter_cve("Remote Registry actif", f"windows {win_ver}", win_build,
                    "Accès registre distant", 5, False)
        ajouter_risque("ELEVE", "Remote Registry Service actif",
                       "Désactiver le service RemoteRegistry")

    # Unquoted paths — ignorer %SystemRoot% et svchost
    VARS_SYSTEME = ["%systemroot%", "%windir%", "system32\\svchost",
                    "\\systemroot\\", "svchost.exe -k"]
    vrais_unquoted = [
        s for s in services.get("unquoted_services", [])
        if not any(v in s.get("chemin", "").lower() for v in VARS_SYSTEME)
    ]
    for svc in vrais_unquoted[:3]:
        ajouter_risque("ELEVE",
                       f"Unquoted Service Path : {svc.get('service','')}",
                       svc.get("chemin", "")[:80])

    # ══════════════════════════════════════════
    # [5] SÉCURITÉ SYSTÈME
    # ══════════════════════════════════════════
    if securite.get("uac_active") is False:
        ajouter_cve("UAC désactivé", f"windows {win_ver}", win_build,
                    "Élévation privilèges", 5, False)
        ajouter_risque("CRITIQUE", "UAC désactivé", "EnableLUA=1")

    if securite.get("lsass_protege") is False:
        ajouter_cve("LSASS non protégé", f"windows {win_ver}", win_build,
                    "Mimikatz possible", 8, False)
        ajouter_risque("CRITIQUE", "LSASS non protégé (RunAsPPL=0)",
                       "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa → RunAsPPL=1")
        
    if securite.get("wdigest_active") is True:
        ajouter_cve("WDigest activé", f"windows {win_ver}", win_build,
                    "MDP en clair mémoire", 5, False)
        ajouter_risque("CRITIQUE", "WDigest activé",
                       "WDigest → UseLogonCredential=0")
        
    if securite.get("bitlocker_actif") is False:
        ajouter_risque("ELEVE", "BitLocker non activé",
                       "Disque non chiffré")

    if securite.get("secure_boot") is False:
        ajouter_risque("MOYEN", "Secure Boot désactivé",
                       "Activer dans BIOS/UEFI")

    if securite.get("credential_guard") is False:
        ajouter_risque("MOYEN", "Credential Guard désactivé",
                       "Activer via Device Guard GPO")

    ps = str(securite.get("ps_execution_policy", ""))
    if ps.lower() in ("unrestricted", "bypass"):
        ajouter_cve("PowerShell Unrestricted", "microsoft powershell",
                    None, f"ExecutionPolicy : {ps}", 5, False)
        ajouter_risque("ELEVE", f"PowerShell : {ps}", "Mettre RemoteSigned")

    defender = securite.get("defender", {})
    if not defender.get("protection_temps_reel"):
        ajouter_risque("CRITIQUE", "Windows Defender désactivé",
                       "Activer la protection temps réel")
    else:
        age = defender.get("age_signatures_jours", 0)
        if age > 7:
            ajouter_risque("ELEVE",
                           f"Signatures Defender obsolètes ({age} jours)",
                           "Mettre à jour les définitions")
    # ══════════════════════════════════════════
    # [6] PATCHES
    # ══════════════════════════════════════════
    if patches.get("windows_update_actif") is False:
        ajouter_cve("Windows Update désactivé", f"windows {win_ver}",
                    win_build, "Non patché", 10, False)
        ajouter_risque("CRITIQUE", "Windows Update désactivé",
                       "Activer wuauserv")

    nb_patches = patches.get("nb_patches", 0)
    if nb_patches == 0:
        nb_patches = len(systeme.get("derniers_patches", []))
    if nb_patches < 5:
        ajouter_risque("ELEVE", f"Peu de patches ({nb_patches} détectés)",
                       "Appliquer tous les patches critiques")

    if patches.get("mises_a_jour_en_attente", 0) > 0:
        ajouter_risque("ELEVE",
                       f"{patches['mises_a_jour_en_attente']} MAJ en attente",
                       "Installer les mises à jour")

    # ══════════════════════════════════════════
    # [7] COMPTES & MOTS DE PASSE
    # ══════════════════════════════════════════

    if comptes.get("nombre_admins", 0) > 2:
        ajouter_risque("ELEVE",
                       f"Trop d'admins : {comptes.get('nombre_admins')}",
                       "Réduire au minimum nécessaire")

    nb_mdp = sum(1 for u in comptes.get("utilisateurs", [])
                 if u.get("actif") and u.get("mdp_expire_jamais"))
    if nb_mdp > 0:
        ajouter_risque("MOYEN", f"{nb_mdp} compte(s) MDP sans expiration",
                       "Configurer une politique d'expiration")

    lon_min = politique.get("longueur_minimale", 0)
    if isinstance(lon_min, int) and lon_min < 8:
        ajouter_risque("ELEVE", f"Longueur MDP min : {lon_min} caractères",
                       "Configurer ≥ 12 caractères via GPO")

    if not politique.get("complexite"):
        ajouter_risque("ELEVE", "Complexité MDP non requise",
                       "Activer PasswordComplexity via GPO")

    seuil = str(politique.get("seuil_verrouillage", "")).lower()
    if "jamais" in seuil or "never" in seuil or seuil in ("0", ""):
        ajouter_risque("ELEVE", "Aucun verrouillage de compte",
                       "LockoutBadCount ≤ 5")

    # ══════════════════════════════════════════
    # [8] LOGS
    # ══════════════════════════════════════════


    echecs = logs.get("echecs_connexion", 0)
    if echecs > 20:
        ajouter_risque("ELEVE", f"{echecs} tentatives connexion (Event 4625)",
                       "Possible brute force")

    if logs.get("audit_efface", 0) > 0:
        ajouter_risque("CRITIQUE", "Journal audit effacé (Event 1102)",
                       "Possible compromission")

    if logs.get("nouveaux_comptes", 0) > 0:
        ajouter_risque("ELEVE",
                       f"{logs['nouveaux_comptes']} nouveaux comptes (Event 4720)",
                       "Vérifier ces comptes")

    # ══════════════════════════════════════════
    # [9] REGISTRE & PERSISTENCE
    # ══════════════════════════════════════════
    alertes = registre.get("alertes", []) if registre else []
    for alerte in alertes:
        cle    = alerte.get("cle", "")
        valeur = alerte.get("valeur", "")
        if "AppInit" in cle and valeur.strip():
            ajouter_cve("AppInit_DLLs", f"windows {win_ver}", win_build,
                        f"DLL = {valeur[:50]}", 5, False)
            ajouter_risque("CRITIQUE", f"AppInit_DLLs : {valeur[:50]}",
                           "Technique persistence malware")
        if "IFEO" in cle:
            ajouter_risque("CRITIQUE", f"IFEO modifié : {cle}",
                           f"Valeur : {valeur[:50]}")
        if "Winlogon" in cle:
            ajouter_risque("CRITIQUE", f"Winlogon modifié : {cle}",
                           f"Valeur : {valeur[:50]}")

    for entry in (persistence.get("autorun_suspects", []) if persistence else []):
        ajouter_risque("ELEVE",
                       f"Autorun suspect : {entry.get('nom','')}",
                       entry.get("valeur", "")[:80])

    # ══════════════════════════════════════════
    # [10] HARDWARE, LIBS, COMPOSANTS, WIFI, DNS
    # ══════════════════════════════════════════
    cpu = hardware.get("cpu", {})
    cpu_vendor = cpu.get("vendor", "").lower()
    cpu_nom    = cpu.get("nom", "").lower()
    if "intel" in cpu_vendor or "intel" in cpu_nom or "genuineintel" in cpu_vendor:
        ajouter_cve("CPU Intel (Spectre/Meltdown)", "intel", None,
                    cpu.get("nom", ""), 8, True)
    elif "amd" in cpu_vendor or "amd" in cpu_nom:
        ajouter_cve("CPU AMD (Spectre)", "amd", None,
                    cpu.get("nom", ""), 5, True)

    bios = hardware.get("bios", {})
    date_bios = bios.get("date", "")
    if date_bios:
        m = re.search(r'20(\d{2})', date_bios)
        if m and int(m.group(1)) < 20:
            ajouter_risque("ELEVE", f"BIOS ancien ({date_bios})",
                           f"Mettre à jour {bios.get('fabricant','')} {bios.get('version','')}")

    # TPM
    tpm = hardware.get("tpm", {})
    if not tpm.get("presente"):
        ajouter_risque("ELEVE", "TPM absent ou désactivé",
                       "TPM requis pour BitLocker")
    else:
        tpm_ver = str(tpm.get("version", ""))
        # MSFT0101 = TPM 2.0
        if tpm_ver.startswith("1."):
            ajouter_risque("MOYEN", f"TPM 1.x ({tpm_ver})", "Migrer vers TPM 2.0")

    # .NET versions installées — version réelle du registre
    for dotnet in bibliotheques.get("dotnet", []):
        ver = normaliser_version(dotnet.get("version", ""))
        if ver:
            ajouter_cve(
                f".NET Framework {ver}",
                "microsoft .net framework",
                ver,
                f".NET Framework {ver} installé (clé registre : {dotnet.get('cle','')})",
                8, True
            )

    # OpenSSL — utiliser version réelle si disponible
    openssl = bibliotheques.get("openssl")
    if openssl:
        ver_raw = openssl.get("version", "")
        # Nettoyer version bizarre (ex: "65263.1213.1.0" → invalide)
        ver_openssl = None
        if ver_raw:
            try:
                major = int(str(ver_raw).split(".")[0])
                if major <= 10:  # OpenSSL max = 3.x
                    ver_openssl = normaliser_version(ver_raw)
                else:
                    # Version corrompue → utiliser "3" ou "1.1" depuis nom fichier
                    chemin = openssl.get("chemin", "")
                    if "libssl-3" in chemin:
                        ver_openssl = "3"
                    elif "libssl-1_1" in chemin:
                        ver_openssl = "1.1"
            except Exception:
                ver_openssl = None

        label = f"OpenSSL {ver_openssl}" if ver_openssl else "OpenSSL (XAMPP)"
        ajouter_cve(label, "openssl", ver_openssl or None,
                    f"Chemin : {openssl.get('chemin','')} — version : {ver_openssl or 'inconnue'}",
                    8, bool(ver_openssl))

    # PowerShell — version réelle du registre
    ps_ver = normaliser_version(bibliotheques.get("powershell_version", ""))
    if ps_ver:
        ajouter_cve(f"PowerShell {ps_ver}", "microsoft powershell",
                    ps_ver, f"PowerShell version {ps_ver} installée", 5, True)

    # WiFi — dédupliquer par SSID
    ssids_vus = set()
    for profil in (wifi.get("profils_faibles", []) if wifi else []):
        ssid = profil.get("ssid", "")
        if ssid and ssid not in ssids_vus:
            ssids_vus.add(ssid)
            ajouter_risque("ELEVE",
                           f"WiFi non sécurisé : {ssid} ({profil.get('auth','')})",
                           "Utiliser WPA2-AES ou WPA3")

    # DNS suspects — nettoyer IPs multiples
    dns_raw = dns_proxy.get("dns_suspects", []) if dns_proxy else []
    dns_set = set()
    for entry in dns_raw:
        for ip in str(entry).replace(",", " ").split():
            ip = ip.strip()
            if ip and re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                dns_set.add(ip)
    for dns in sorted(dns_set):
        ajouter_risque("MOYEN", f"DNS suspect : {dns}",
                       "Vérifier ce DNS — peut être DNS d'antivirus ")

    # Processus depuis Temp — dédupliquer par nom
    noms_proc_vus = set()
    for proc in (processus.get("processus_suspects", []) if processus else []):
        nom_proc = proc.get("nom", "")
        if nom_proc and nom_proc not in noms_proc_vus:
            noms_proc_vus.add(nom_proc)
            ajouter_risque("ELEVE",
                           f"Processus depuis Temp : {nom_proc}",
                           f"Vérifier : {proc.get('exe','')[:70]}")

    # Drivers vulnérables
    for drv in (drivers.get("drivers_vulnerables", []) if drivers else []):
        ajouter_cve(f"Driver vulnérable : {drv.get('nom','')}",
                    f"windows {win_ver}", win_build,
                    drv.get("risque", ""), 5, False)
        ajouter_risque("CRITIQUE", f"Driver vulnérable : {drv.get('nom','')}",
                       drv.get("risque", ""))


    # ── Services tiers actifs → CVE NVD ──
    services_actifs = services.get("services_actifs", [])
    VARS_SYSTEME_SVC = ["%systemroot%", "%windir%", "%systemdrive%",
                        "svchost.exe", "system32"]
    vus_services = set()
    for svc in services_actifs:
        chemin = svc.get("chemin", "").lower()
        nom    = svc.get("nom", "").lower()
        display = svc.get("display", "")

        # Ignorer services Windows natifs
        if any(v in chemin for v in VARS_SYSTEME_SVC):
            continue

        # Extraire nom lisible depuis display ou chemin
        nom_recherche = None
        if display and not display.startswith("@%"):
            # Ex: "Avast Browser Update Service (avast)" → "avast browser"
            nom_propre = display.split("(")[0].strip().lower()
            if len(nom_propre) > 3:
                nom_recherche = nom_propre
        elif chemin:
            # Ex: "C:\Program Files\BraveSoftware\..." → "brave"
            import re as _re
            m = _re.search(r"program files[\\x86]*\\([^\\]+)\\", chemin)
            if m:
                nom_recherche = m.group(1).lower()

        if not nom_recherche or nom_recherche in vus_services:
            continue

        # Éviter doublons de noms similaires
        nom_court = nom_recherche.split()[0]  # Premier mot
        if nom_court in vus_services:
            continue
        vus_services.add(nom_court)

        # Récupérer version du service
        ver_svc = normaliser_version(svc.get("version", ""))
        titre_svc = display[:50] if display and not display.startswith('@') else nom.title()
        ajouter_cve(
            f"Service tiers : {titre_svc}",
            nom_recherche,
            ver_svc or None,
            f"Service actif : {chemin[:60]} — version : {ver_svc or 'inconnue'}",
            limite=5, version_requise=bool(ver_svc)
        )

    # ── GPU Intel/AMD → CVE drivers ──
    gpu = hardware.get("gpu", {})
    gpu_nom = gpu.get("nom", "").lower()
    gpu_ver = normaliser_version(gpu.get("version_driver") or gpu.get("version", ""))
    if gpu_nom:
        if "intel" in gpu_nom:
            ajouter_cve(
                f"GPU Intel : {gpu.get('nom','')}",
                "intel", gpu_ver or None,
                f"Driver GPU Intel version : {gpu_ver or 'inconnue'}",
                5, bool(gpu_ver)
            )
        elif "nvidia" in gpu_nom:
            ajouter_cve(
                f"GPU NVIDIA : {gpu.get('nom','')}",
                "nvidia", gpu_ver or None,
                f"Driver GPU NVIDIA version : {gpu_ver or 'inconnue'}",
                5, bool(gpu_ver)
            )
        elif "amd" in gpu_nom or "radeon" in gpu_nom:
            ajouter_cve(
                f"GPU AMD : {gpu.get('nom','')}",
                "amd", gpu_ver or None,
                f"Driver GPU AMD version : {gpu_ver or 'inconnue'}",
                5, bool(gpu_ver)
            )

    # ── Drivers kernel tiers → risque config ──
    for drv in drivers.get("drivers_tiers", []) if drivers else []:
        nom_drv = drv.get("nom", "")
        chemin_drv = drv.get("chemin", "")
        ajouter_risque("ELEVE",
                       f"Driver kernel tiers : {nom_drv}",
                       f"Driver hors système : {chemin_drv[:80]} — vérifier sa légitimité")


    if conn_cpe:
        conn_cpe.close()
    conn.close()

    # ══════════════════════════════════════════
    # RÉSUMÉ FINAL
    # ══════════════════════════════════════════
    toutes_cves = []
    for cat in resultats["categories"]:
        toutes_cves += cat["cves"]

    # Vérification déduplication finale
    uniques = {c["cve_id"]: c for c in toutes_cves}
    assert len(uniques) == len(cve_vus), "BUG: doublons détectés !"

    resultats["resume"]["cve_uniques"]      = len(uniques)
    resultats["resume"]["critique"]         = len([c for c in uniques.values() if c.get("niveau") == "CRITIQUE"])
    resultats["resume"]["eleve"]            = len([c for c in uniques.values() if c.get("niveau") == "ELEVE"])
    resultats["resume"]["moyen"]            = len([c for c in uniques.values() if c.get("niveau") == "MOYEN"])
    resultats["resume"]["risques_config"]   = len(resultats["risques_config"])
    resultats["resume"]["risques_critique"] = len([r for r in resultats["risques_config"] if r["niveau"] == "CRITIQUE"])
    resultats["resume"]["risques_eleve"]    = len([r for r in resultats["risques_config"] if r["niveau"] == "ELEVE"])

    # Trier risques
    ordre = {"CRITIQUE": 0, "ELEVE": 1, "MOYEN": 2, "FAIBLE": 3}
    resultats["risques_config"].sort(key=lambda x: ordre.get(x["niveau"], 4))

    with open(RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    return resultats
if __name__ == "__main__":
    resultats = lancer_matching()
    input("\nAppuie sur Entrée pour fermer...")
