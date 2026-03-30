import json
import os
import datetime
import webbrowser

BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CVE_PATH  = os.path.join(BASE_DIR, "data",    "cve_results.json")
SCAN_PATH = os.path.join(BASE_DIR, "data",    "scan_complet.json")
AI_PATH   = os.path.join(BASE_DIR, "data",    "rapport_complet.json")
HTML_PATH = os.path.join(BASE_DIR, "data",    "rapport_auditai.html")
CSS_PATH  = os.path.join(BASE_DIR, "assets", "style.css")


# ══════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════

def couleur_niveau(niveau):
    return {
        "CRITIQUE": ("#ef4444", "🔴"),
        "ELEVE":    ("#f97316", "🟠"),
        "MOYEN":    ("#eab308", "🟡"),
        "FAIBLE":   ("#22c55e", "🟢"),
    }.get(niveau, ("#6b7280", "⚪"))


def badge(niveau):
    c, icone = couleur_niveau(niveau)
    return (f'<span class="badge" style="background:{c};">'
            f'{icone} {niveau}</span>')


def couleur_score_cve(score):
    try:
        s = float(score)
        if s >= 9.0: return "#ef4444"
        if s >= 7.0: return "#f97316"
        if s >= 4.0: return "#eab308"
        return "#22c55e"
    except Exception:
        return "#6b7280"


def score_global(cve_data, rapport_ai=None):
    if rapport_ai:
        s = rapport_ai.get("resume_global", {}).get("score_securite", 0)
        if s: return s
    r  = cve_data.get("resume", {})
    p  = r.get("critique", 0) * 8
    p += r.get("eleve", 0)    * 4
    p += r.get("moyen", 0)    * 2
    p += r.get("risques_critique", 0) * 6
    p += r.get("risques_eleve", 0)    * 3
    return max(0, 100 - p)


def charger_css():
    """Charge le fichier CSS externe."""
    if os.path.exists(CSS_PATH):
        with open(CSS_PATH, "r", encoding="utf-8") as f:
            return f.read()
    return ""  # Fallback si CSS absent

def fusionner_problemes(cve_data, rapport_ai):
    """Chaque problème = 1 entrée unique avec analyse IA."""

    ai_risques_list = []
    ai_cve_list     = []
    if rapport_ai:
        ai_risques_list = rapport_ai.get("analyses_risques", [])
        ai_cve_list     = rapport_ai.get("analyses_cve", [])

    STOPWORDS = {
        "actif", "activer", "désactiver", "désactivé", "activé", "windows",
        "depuis", "pour", "avec", "sans", "dans", "les", "des", "une", "non",
        "trop", "peu", "aucun", "compte", "comptes", "service", "tiers"
    }

    def mots_cles(texte):
        return {
            m.lower()
            for m in str(texte).replace("(", " ").replace(")", " ").split()
            if len(m) > 3 and m.lower() not in STOPWORDS
        }

    def meilleure_ia(titre, liste):
        mc = mots_cles(titre)
        if not mc:
            return None
        best, best_score = None, 0
        for a in liste:
            # Chercher dans tous les champs titre
            txt = " ".join(str(a.get(k, "")) for k in
                           ["titre", "titre_fr", "titre_original"])
            communs = mc & mots_cles(txt)
            if len(communs) > best_score:
                best_score = len(communs)
                best = a
        return best if best_score >= 1 else None

    def get_ia(titre, prefer_cve=False):
        listes = ([ai_cve_list, ai_risques_list] if prefer_cve
                  else [ai_risques_list, ai_cve_list])
        for lst in listes:
            a = meilleure_ia(titre, lst)
            if a:
                return a
        return {}

    def cle_dedup(titre):
        return frozenset(sorted(mots_cles(titre))[:5])

    problemes = []
    vus = set()

    # 1. Catégories CVE
    for cat in cve_data.get("categories", []):
        titre = cat.get("titre", "")
        cves  = cat.get("cves", [])
        if not cves:
            continue
        cle = cle_dedup(titre)
        if cle in vus:
            continue
        vus.add(cle)

        niv = "MOYEN"
        for c in cves:
            if c.get("niveau") == "CRITIQUE": niv = "CRITIQUE"; break
            if c.get("niveau") == "ELEVE":    niv = "ELEVE"

        ai = get_ia(titre, prefer_cve=True)
        problemes.append({
            "titre":          titre,
            "niveau":         niv,
            "cves":           cves,
            "explication":    ai.get("explication",    ""),
            "recommandation": ai.get("recommandation", ""),
            "impact":         ai.get("impact",         ""),
        })

    # 2. Risques config
    for r in cve_data.get("risques_config", []):
        titre  = r.get("titre", "")
        detail = r.get("detail", "")
        cle    = cle_dedup(titre)
        if cle in vus:
            continue
        vus.add(cle)

        ai = get_ia(titre, prefer_cve=False)
        problemes.append({
            "titre":          titre,
            "niveau":         r.get("niveau", "MOYEN"),
            "cves":           [],
            "explication":    ai.get("explication",    ""),
            "recommandation": ai.get("recommandation", "") or detail,
            "impact":         ai.get("impact",         ""),
        })

    ordre = {"CRITIQUE": 0, "ELEVE": 1, "MOYEN": 2, "FAIBLE": 3}
    problemes.sort(key=lambda x: ordre.get(x["niveau"], 4))
    return problemes


# ══════════════════════════════════════════════
#  BLOCS HTML
# ══════════════════════════════════════════════

def html_sysinfo(scan):
    s    = scan.get("systeme", {})
    hw   = scan.get("hardware", {})
    p    = scan.get("patches", {})
    bios = hw.get("bios", {})
    tpm  = hw.get("tpm", {})
    tpm_ver   = str(tpm.get("version", ""))
    tpm_label = "TPM 2.0 ✅" if "MSFT0101" in tpm_ver else ("Présent" if tpm.get("presente") else "Absent ❌")
    nb_p  = p.get("nb_patches", 0) or len(s.get("derniers_patches", []))
    cpu   = hw.get("cpu", {}).get("nom", "")[:38]
    wdisp = s.get("windows_display", "")

    def card(label, val, color="#e2e8f0"):
        return (f'<div class="sysinfo-card">'
                f'<div class="sysinfo-label">{label}</div>'
                f'<div class="sysinfo-value" style="color:{color};">{val}</div>'
                f'</div>')

    c_ok  = "#22c55e"
    c_ko  = "#ef4444"
    c_def = "#e2e8f0"

    items = (
        card("🖥️ Hostname",    s.get("hostname", ""))
      + card("👤 Utilisateur", s.get("username", ""))
      + card("💻 Windows",     f"Windows {s.get('windows_version','?')} {wdisp}")
      + card("🏗️ Build",       s.get("windows_build", "?"))
      + card("💾 RAM",         f"{s.get('ram_gb','?')} GB")
      + card("⚙️ CPU",         cpu or "N/A")
      + card("📋 BIOS",        bios.get("date", "N/A"))
      + card("🔑 TPM",         tpm_label, c_ok if "MSFT0101" in tpm_ver else c_ko)
      + card("🔄 Patches",     f"{nb_p} installés", c_ok if nb_p > 5 else c_ko)
      + card("🔒 Admin",       "Oui ⚠️" if s.get("est_admin") else "Non ✅",
             c_ko if s.get("est_admin") else c_ok)
    )
    return f'<div class="sysinfo-grid">{items}</div>'


def html_securite_tableau(scan):
    sec  = scan.get("securite", {})
    res  = scan.get("reseau", {})
    svc  = scan.get("services", {})
    pat  = scan.get("patches", {})
    defe = sec.get("defender", {})

    def ligne(label, ok, tok="✅ Actif", tko="❌ Inactif"):
        cls = "ok" if ok else "ko"
        txt = tok if ok else tko
        return (f'<tr><td class="label">{label}</td>'
                f'<td class="{cls}">{txt}</td></tr>')

    rows = (
        ligne("UAC",              sec.get("uac_active", False))
      + ligne("LSASS Protégé",    sec.get("lsass_protege", False))
      + ligne("WDigest",          not sec.get("wdigest_active", True), "✅ Désactivé", "❌ Actif")
      + ligne("BitLocker",        sec.get("bitlocker_actif", False))
      + ligne("Secure Boot",      sec.get("secure_boot", False))
      + ligne("Credential Guard", sec.get("credential_guard", False))
      + ligne("Defender",         defe.get("protection_temps_reel", False))
      + ligne("SMBv1",            not res.get("smb1_active", False), "✅ Désactivé", "❌ Actif")
      + ligne("SMB Signing",      res.get("smb_signing", False))
      + ligne("Pare-feu",         not res.get("parefeu_desactive", True), "✅ Actif", "❌ Désactivé")
      + ligne("RDP",              not res.get("rdp_active", False), "✅ Désactivé", "❌ Actif")
      + ligne("LLMNR",            not res.get("llmnr_active", True), "✅ Désactivé", "❌ Actif")
      + ligne("Print Spooler",    not svc.get("spooler_actif", False), "✅ Désactivé", "❌ Actif")
      + ligne("Windows Update",   pat.get("windows_update_actif", False))
    )
    return (f'<table class="secu-table">'
            f'<thead><tr><th>Contrôle</th><th>État</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>')


def html_wifi_dns(scan):
    wifi  = scan.get("wifi", {})
    dns_p = scan.get("dns_proxy", {})

    # WiFi
    ssids  = set()
    wifi_h = ""
    for p in wifi.get("profils_faibles", []):
        ssid = p.get("ssid", "")
        if ssid and ssid not in ssids:
            ssids.add(ssid)
            wifi_h += (f'<div class="wifi-item">⚠️ {ssid} — '
                       f'<span style="color:#94a3b8;">{p.get("auth","")}</span></div>')
    if not wifi_h:
        wifi_h = '<div class="ok-msg">✅ Tous les profils WiFi sont sécurisés</div>'

    # DNS
    dns_set = set()
    for entry in dns_p.get("dns_suspects", []):
        for ip in str(entry).replace(",", " ").split():
            if ip.strip():
                dns_set.add(ip.strip())
    dns_h = ""
    for dns in sorted(dns_set):
        dns_h += (f'<div class="dns-item">⚠️ {dns} '
                  f'<span style="color:#64748b;font-size:13px;">— DNS non standard</span></div>')
    if not dns_h:
        dns_h = '<div class="ok-msg">✅ Serveurs DNS standards</div>'

    return wifi_h, dns_h


def html_problemes(problemes):
    """Génère les cartes de problèmes unifiées."""
    if not problemes:
        return '<div class="ok-msg" style="padding:20px;text-align:center;">✅ Aucun problème détecté</div>'

    html = ""
    for prob in problemes:
        niv   = prob["niveau"]
        titre = prob["titre"]
        cves  = prob["cves"]
        explic = prob.get("explication", "")
        reco   = prob.get("recommandation", "")
        impact = prob.get("impact", "")

        col, icone = couleur_niveau(niv)

        # Titre tronqué
        titre_aff = titre if len(titre) <= 55 else titre[:52] + "..."

        # CVE IDs
        cve_html = ""
        if cves:
            tags = "".join(
                f'<span class="cve-tag">{c["cve_id"]} '
                f'<span class="cve-score" style="color:{couleur_score_cve(float(c.get("score",0)))};">'
                f'({c.get("score","")})</span></span>'
                for c in cves[:6]
            )
            if len(cves) > 6:
                tags += f'<span style="color:#64748b;font-size:13px;font-style:italic;"> + {len(cves)-6} autres</span>'
            cve_html = f'<div class="cve-list">{tags}</div>'

        # Explication
        explic_html = (f'<div class="problem-explication">{explic}</div>'
                       if explic else "")

        # Impact
        impact_html = ""
        if impact:
            impact_html = (f'<div class="problem-impact">'
                           f'<span class="impact-label">⚡ Impact :</span>'
                           f'<span class="impact-text">{impact}</span>'
                           f'</div>')

        # Recommandation
        reco_html = ""
        if reco:
            reco_html = (f'<div class="problem-reco">'
                         f'<div class="reco-label">✅ Que faire :</div>'
                         f'<div class="reco-text">{reco}</div>'
                         f'</div>')

        html += (f'<div class="problem-card" style="border-left-color:{col};">'
                 f'<div class="problem-header">'
                 f'<div class="problem-title">{icone} {titre_aff}</div>'
                 f'{badge(niv)}'
                 f'</div>'
                 f'{cve_html}'
                 f'{explic_html}'
                 f'{impact_html}'
                 f'{reco_html}'
                 f'</div>')

    return html


# ══════════════════════════════════════════════
#  RAPPORT HTML COMPLET
# ══════════════════════════════════════════════

def generer_html(cve_data, scan, rapport_ai=None):
    sys_info = scan.get("systeme", {})
    resume   = cve_data.get("resume", {})
    hostname = sys_info.get("hostname", "PC")
    win_ver  = sys_info.get("windows_version", "11")
    win_disp = sys_info.get("windows_display", "")
    arch     = sys_info.get("architecture", "AMD64")
    date_str = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M")

    score    = score_global(cve_data, rapport_ai)
    nb_crit  = resume.get("critique", 0)
    nb_elev  = resume.get("eleve", 0)
    nb_moyen = resume.get("moyen", 0)
    nb_uniq  = resume.get("cve_uniques", 0)
    nb_ris   = resume.get("risques_config", 0)
    nb_rcrit = resume.get("risques_critique", 0)

    if score >= 75:   sc_col, sc_label = "#22c55e", "ACCEPTABLE"
    elif score >= 50: sc_col, sc_label = "#eab308", "RISQUÉ"
    else:             sc_col, sc_label = "#ef4444", "CRITIQUE"

    # Message IA
    if rapport_ai:
        msg     = rapport_ai.get("resume_global", {}).get("conseil", "")
        actions = rapport_ai.get("resume_global", {}).get("actions_prioritaires", [])
    else:
        msg     = f"Le système présente {nb_crit} CVE critiques et {nb_rcrit} risques critiques."
        actions = []

    # Actions IA
    act_html = ""
    if actions:
        items = "".join(
            f'<div class="ai-actions-item">{i}. {a}</div>'
            for i, a in enumerate(actions[:3], 1)
        )
        act_html = (f'<div class="ai-actions">'
                    f'<div class="ai-actions-title">🤖 Actions prioritaires</div>'
                    f'{items}</div>')

    # Donut SVG
    total_d = max(nb_crit + nb_elev + nb_moyen, 1)
    r_d = 40
    circ = 2 * 3.14159 * r_d

    def arc(pct, offset, color):
        dash = pct * circ
        gap  = circ - dash
        off  = -offset * circ
        return (f'<circle cx="60" cy="60" r="{r_d}" fill="none" stroke="{color}" '
                f'stroke-width="16" stroke-dasharray="{dash:.1f} {gap:.1f}" '
                f'stroke-dashoffset="{off:.1f}" transform="rotate(-90 60 60)"/>')

    donut = (f'<svg width="120" height="120" viewBox="0 0 120 120">'
             f'<circle cx="60" cy="60" r="{r_d}" fill="none" stroke="#1e2d45" stroke-width="16"/>'
             + arc(nb_crit/total_d, 0, "#ef4444")
             + arc(nb_elev/total_d, nb_crit/total_d, "#f97316")
             + arc(nb_moyen/total_d, (nb_crit+nb_elev)/total_d, "#eab308")
             + f'<text x="60" y="56" text-anchor="middle" fill="white" font-size="18" '
               f'font-weight="bold" font-family="monospace">{nb_uniq}</text>'
               f'<text x="60" y="70" text-anchor="middle" fill="#94a3b8" font-size="9">CVE</text>'
               f'</svg>')

    # Fusionner problèmes
    problemes = fusionner_problemes(cve_data, rapport_ai)
    nb_prob   = len(problemes)

    wifi_h, dns_h = html_wifi_dns(scan)

    # CSS — charger depuis fichier externe
    css = charger_css()

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AuditAI — {hostname}</title>
  <style>
{css}

/* Styles dynamiques (couleurs selon score) */
.banner       {{ border: 2px solid {sc_col}40; }}
.banner-label {{ color: {sc_col}; }}
.bar-fill     {{ background: {sc_col}; width: {score}%; }}
.score-num    {{ color: {sc_col}; }}
  </style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="header-top">
    <div class="logo">
      <div class="logo-icon">🛡️</div>
      <div>
        <div class="logo-text">AuditAI</div>
        <div class="logo-sub">Rapport de Sécurité Windows</div>
      </div>
    </div>
    <div class="meta">
      <strong>{hostname}</strong>
      Généré le {date_str}<br>
      Windows {win_ver} {win_disp} — {arch}
    </div>
  </div>

  <div class="banner">
    <div class="banner-icon">{'🔴' if score<40 else '🟠' if score<70 else '🟢'}</div>
    <div style="flex:1;">
      <div class="banner-label">
        {sc_label} — {'Sécurité compromise' if score<40 else 'Sécurité à risque' if score<70 else 'Sécurité acceptable'}
      </div>
      <div class="banner-msg">{msg}</div>
      <div class="score-bar">
        <span class="score-label">SCORE</span>
        <div class="bar-track"><div class="bar-fill"></div></div>
        <span class="score-num">{score}/100</span>
      </div>
      {act_html}
    </div>
  </div>
</div>

<!-- CONTENU -->
<div class="container">

  <!-- STATISTIQUES -->
  <div class="stats">
    <div class="stat"><div class="stat-n" style="color:#ef4444;">{nb_crit}</div><div class="stat-l">CVE Critiques</div></div>
    <div class="stat"><div class="stat-n" style="color:#f97316;">{nb_elev}</div><div class="stat-l">CVE Élevées</div></div>
    <div class="stat"><div class="stat-n" style="color:#eab308;">{nb_moyen}</div><div class="stat-l">CVE Moyennes</div></div>
    <div class="stat"><div class="stat-n" style="color:#60a5fa;">{nb_uniq}</div><div class="stat-l">CVE Totales</div></div>
    <div class="stat"><div class="stat-n" style="color:#a855f7;">{nb_ris}</div><div class="stat-l">Risques Config</div></div>
    <div class="stat"><div class="stat-n" style="color:#ef4444;">{nb_prob}</div><div class="stat-l">Problèmes Uniques</div></div>
  </div>

  <!-- INFORMATIONS SYSTÈME -->
  <div class="section">
    <div class="section-title">🖥️ Informations Système <span class="sec-badge">SYSTÈME</span></div>
    {html_sysinfo(scan)}
  </div>

  <!-- SÉCURITÉ + DONUT -->
  <div class="two-col">
    <div>
      <div class="section-title">🔒 Contrôles de Sécurité <span class="sec-badge">ÉTAT</span></div>
      {html_securite_tableau(scan)}
    </div>
    <div>
      <div class="section-title">📊 Répartition CVE <span class="sec-badge">ANALYSE</span></div>
      <div class="panel donut-container">
        {donut}
        <div class="donut-legend">
          <div class="legend-item">
            <div class="legend-dot" style="background:#ef4444;"></div>
            <span class="legend-label">Critique ({nb_crit})</span>
          </div>
          <div class="legend-item">
            <div class="legend-dot" style="background:#f97316;"></div>
            <span class="legend-label">Élevé ({nb_elev})</span>
          </div>
          <div class="legend-item">
            <div class="legend-dot" style="background:#eab308;"></div>
            <span class="legend-label">Moyen ({nb_moyen})</span>
          </div>
        </div>
      </div>

      <div class="section-title" style="margin-top:28px;">📶 WiFi <span class="sec-badge">RÉSEAU</span></div>
      <div class="panel">{wifi_h}</div>

      <div class="section-title" style="margin-top:28px;">🔍 DNS <span class="sec-badge">RÉSEAU</span></div>
      <div class="panel">{dns_h}</div>
    </div>
  </div>

  <!-- PROBLÈMES UNIFIÉS -->
  <div class="section">
    <div class="section-title">
      🛡️ Problèmes de Sécurité Détectés
      <span class="sec-badge">{nb_prob} UNIQUES</span>
    </div>
    {html_problemes(problemes)}
  </div>

</div>

<!-- FOOTER -->
<div class="footer">
  AuditAI v1.0 · Rapport du {date_str} · Windows {win_ver} {win_disp} · PFE 2026<br>
  <span class="footer-note">Les CVE Windows OS sont indicatives — Valider via MSRC Security Update Guide</span>
</div>

</body>
</html>"""


# ══════════════════════════════════════════════
#  POINT D'ENTRÉE
# ══════════════════════════════════════════════

def generer_rapport():
    

    for path, nom in [(CVE_PATH, "cve_results.json"), (SCAN_PATH, "scan_complet.json")]:
        if not os.path.exists(path):
          
            return None

    with open(CVE_PATH,  "r", encoding="utf-8") as f: cve_data = json.load(f)
    with open(SCAN_PATH, "r", encoding="utf-8") as f: scan     = json.load(f)

    rapport_ai = None
    if os.path.exists(AI_PATH):
        with open(AI_PATH, "r", encoding="utf-8") as f:
            rapport_ai = json.load(f)
        
    else:
        print("  Sans IA — lancez Ai_engine.py pour enrichir le rapport")

    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
    html = generer_html(cve_data, scan, rapport_ai)

    with open(HTML_PATH, "w", encoding="utf-8") as f:
        f.write(html)
    

    # PDF si wkhtmltopdf disponible
    pdf_path = HTML_PATH.replace(".html", ".pdf")
    WKHTML   = [
        os.path.join(BASE_DIR, "bin", "wkhtmltopdf.exe"),
        r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe",
    ]
    wk = next((p for p in WKHTML if os.path.exists(p)), None)
    if wk:
            import subprocess
            subprocess.run(
                [wk, "--enable-local-file-access", "--encoding", "UTF-8",
                 "--quiet", "--page-size", "A4",
                 "--margin-top", "10mm", "--margin-bottom", "10mm",
                 "--margin-left", "10mm", "--margin-right", "10mm",
                 HTML_PATH, pdf_path],
                check=True, timeout=60
            )
            print(f"  ✅ PDF : {pdf_path}")
            webbrowser.open(f"file:///{pdf_path.replace(os.sep, '/')}")
            return pdf_path
        
           

    webbrowser.open(f"file:///{HTML_PATH.replace(os.sep, '/')}")
    
    return HTML_PATH


if __name__ == "__main__":
    generer_rapport()
   
