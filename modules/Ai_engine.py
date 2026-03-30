
import os
import json
import datetime
import time
from dotenv import load_dotenv
load_dotenv()

try:
    from google import genai
    from google.genai import types
    GENAI_OK = True
except ImportError:
    try:
        import google.generativeai as genai_old
        GENAI_OK = True
        GENAI_V2 = False
    except ImportError:
        GENAI_OK = False


BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CVE_PATH      = os.path.join(BASE_DIR, "data", "cve_results.json")
SCAN_PATH     = os.path.join(BASE_DIR, "data", "scan_complet.json")
RAPPORT_PATH  = os.path.join(BASE_DIR, "data", "rapport_complet.json")

GEMINI_KEY    = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL  = os.getenv("GEMINI_MODEL")


# ══════════════════════════════════════════════
#  CLIENT GEMINI
# ══════════════════════════════════════════════

def init_gemini():
    """Initialise le client Gemini."""
    if not GEMINI_KEY:
        return None
    try:
        client = genai.Client(api_key=GEMINI_KEY)
        return client
    except Exception as e:
        return None


def appeler_gemini(client, prompt, max_tokens=1500):
    """
    Appelle Gemini et retourne le texte.
    Retry automatique si rate limit.
    Timeout de 30s par requête.
    """
    import threading

    for tentative in range(3):
        resultat = [None]
        erreur   = [None]

        def appel():
            try:
                response = client.models.generate_content(
                    model=GEMINI_MODEL,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        max_output_tokens=max_tokens,
                        temperature=0.3,
                    )
                )
                resultat[0] = response.text.strip()
            except Exception as e:
                erreur[0] = str(e)

        thread = threading.Thread(target=appel)
        thread.start()
        thread.join(timeout=45)  # Timeout 45s

        if thread.is_alive():
            time.sleep(5)
            continue

        if resultat[0]:
            return resultat[0]

        if erreur[0]:
            err = erreur[0].lower()
            if "429" in err or "quota" in err or "rate" in err:
                wait = (tentative + 1) * 15
                time.sleep(wait)
            else:
                return None
    return None


def appeler_gemini_json(client, prompt, max_tokens=2000):
    """
    Appelle Gemini et retourne du JSON parsé.
    Extrait le premier JSON valide — ignore le texte extra.
    """
    import re as _re

    texte = appeler_gemini(client, prompt, max_tokens)
    if not texte:
        return None

    texte = texte.strip()

    # Supprimer blocs markdown
    match_md = _re.search(r"```(?:json)?\s*([\s\S]*?)```", texte)
    if match_md:
        texte = match_md.group(1).strip()

    # Trouver le premier { ou [
    debut_brace  = texte.find("{")
    debut_crochet = texte.find("[")

    if debut_brace == -1 and debut_crochet == -1:
        return None

    # Prendre le premier qui apparaît
    if debut_brace != -1 and (debut_crochet == -1 or debut_brace < debut_crochet):
        ouvre, ferme, debut = "{", "}", debut_brace
    else:
        ouvre, ferme, debut = "[", "]", debut_crochet

    # Trouver la fermeture correspondante
    niveau = 0
    fin    = -1
    for i in range(debut, len(texte)):
        if texte[i] == ouvre:
            niveau += 1
        elif texte[i] == ferme:
            niveau -= 1
            if niveau == 0:
                fin = i + 1
                break

    if fin == -1:
        return None

    json_str = texte[debut:fin].strip()

    # Parser avec nettoyage
    for essai in range(2):
        try:
            return json.loads(json_str)
        except Exception as e:
            if essai == 0:
                # Supprimer trailing comma avant } ou ]
                json_str = _re.sub(r",\s*([}\]])", r"\1", json_str)
            else:
                return None
    return None

def analyser_risques_config(client, risques_config, systeme):
    """
    Gemini analyse TOUS les risques de configuration.
    Chaque risque reçoit une analyse SPÉCIFIQUE et UNIQUE.
    """
    if not risques_config:
        return []

    hostname = systeme.get("hostname", "PC")
    win_ver  = systeme.get("windows_version", "11")
    build    = systeme.get("windows_build", "")

    # Préparer liste numérotée avec contexte
    risques_str = ""
    for i, r in enumerate(risques_config[:20], 1):
        titre  = r.get("titre", "")
        detail = r.get("detail", "")
        niveau = r.get("niveau", "ELEVE")
        risques_str += f"{i}. [{niveau}] {titre}\n"
        if detail and detail != titre:
            risques_str += f"   Info : {detail[:100]}\n"

    nb = min(len(risques_config), 20)

    prompt = f"""
Voici {nb} risques de sécurité détectés sur {hostname} (Windows {win_ver} {build}).

RISQUES :
{risques_str}

Génère une analyse JSON pour CHAQUE risque dans l'ordre.
RÈGLE : chaque analyse doit être UNIQUE et SPÉCIFIQUE au risque de même numéro.
Ne jamais réutiliser la même explication pour deux risques différents.

JSON (sans markdown) :
{{
  "analyses": [
    {{
      "titre_original": "Titre EXACT copié du risque (ex: LSASS non protégé (RunAsPPL=0))",
      "explication": "2 phrases spécifiques sur ce risque : pourquoi c'est dangereux sur Windows 11",
      "impact": "Conséquence concrète si exploité (spécifique à ce risque)",
      "recommandation": "Correction précise avec commandes/clés registre/GPO pour ce risque"
    }}
  ]
}}

Génère exactement {nb} analyses. Langue : français."""

    result = appeler_gemini_json(client, prompt, max_tokens=4000)

    if result and "analyses" in result:
        analyses = result["analyses"]
        sortie = []
        for i, risque in enumerate(risques_config[:20]):
            titre_exact = risque.get("titre", "")
            detail      = risque.get("detail", "")

            if i < len(analyses):
                a = analyses[i]
                sortie.append({
                    "titre":          a.get("titre_original", titre_exact),
                    "titre_original": titre_exact,  # ← titre EXACT de cve_matcher
                    "niveau":         risque.get("niveau", "ELEVE"),
                    "explication":    a.get("explication", ""),
                    "recommandation": a.get("recommandation", detail),
                    "impact":         a.get("impact", ""),
                })
            else:
                sortie.append({
                    "titre":          titre_exact,
                    "titre_original": titre_exact,
                    "niveau":         risque.get("niveau", "ELEVE"),
                    "explication":    detail,
                    "recommandation": detail,
                    "impact":         "",
                })
        return sortie

    # Fallback sans IA
    return [{
        "titre":          r.get("titre", ""),
        "titre_original": r.get("titre", ""),
        "niveau":         r.get("niveau", "ELEVE"),
        "explication":    r.get("detail", ""),
        "recommandation": r.get("detail", ""),
        "impact":         "",
    } for r in risques_config[:20]]


def analyser_cve_categories(client, categories, systeme):
    """
    Gemini analyse TOUTES les catégories CVE en UNE SEULE requête.
    Plus rapide, moins de risque de blocage.
    """
    if not categories:
        return []

    # Préparer toutes les catégories en une seule fois
    cats_str = ""
    for i, cat in enumerate(categories):
        titre    = cat.get("titre", "")
        cpe      = cat.get("cpe", "")
        nb       = cat.get("nb_cves", 0)
        contexte = cat.get("contexte", "")
        cves     = cat.get("cves", [])
        top_cve  = f"{cves[0]['cve_id']} (score {cves[0]['score']})" if cves else ""
        cats_str += f"{i+1}. [{cpe}] {titre} — {nb} CVE — top: {top_cve}\n"

    prompt = f"""
Analyse ces {len(categories)} catégories de vulnérabilités CVE détectées sur Windows 11.
IMPORTANT : Chaque analyse DOIT être SPÉCIFIQUE au sujet de la catégorie (titre).
Ne répète pas la même analyse pour des catégories différentes.

CATÉGORIES :
{cats_str}

Génère un JSON (sans markdown) avec une analyse UNIQUE et SPÉCIFIQUE pour chaque catégorie :
{{
  "analyses": [
    {{
      "titre_fr": "Titre court et spécifique au sujet",
      "explication": "2-3 phrases spécifiques au TITRE de cette catégorie (pas générique)",
      "impact": "Impact concret et spécifique à cette vulnérabilité",
      "recommandation": "Action corrective précise pour CE problème spécifique",
      "urgence": "IMMÉDIATE|HAUTE|MODÉRÉE"
    }}
  ]
}}

Règle absolue : si le titre mentionne LLMNR → parler de LLMNR.
Si le titre mentionne Pare-feu → parler du pare-feu.
Si le titre mentionne OpenSSL → parler d'OpenSSL.
Génère exactement {len(categories)} analyses dans le même ordre. En français."""

    result = appeler_gemini_json(client, prompt, max_tokens=2000)

    sortie = []
    analyses_ia = result.get("analyses", []) if result else []

    for i, cat in enumerate(categories):
        titre    = cat.get("titre", "")
        cpe      = cat.get("cpe", "")
        nb       = cat.get("nb_cves", 0)
        contexte = cat.get("contexte", "")
        cves     = cat.get("cves", [])

        # IA ou fallback
        if i < len(analyses_ia):
            a = analyses_ia[i]
        else:
            a = {}

        sortie.append({
            "titre_original": titre,
            "titre_fr":       a.get("titre_fr", titre),
            "cpe":            cpe,
            "nb_cves":        nb,
            "cves_ids":       [c["cve_id"] for c in cves[:5]],
            "score_max":      max((float(c.get("score", 0) or 0) for c in cves), default=0),
            "niveau":         cves[0].get("niveau", "ELEVE") if cves else "ELEVE",
            "explication":    a.get("explication", contexte),
            "impact":         a.get("impact", "Impact potentiel sur la sécurité"),
            "recommandation": a.get("recommandation", "Appliquer les patches disponibles"),
            "urgence":        a.get("urgence", "HAUTE"),
        })
    return sortie


# ══════════════════════════════════════════════
#  RÉSUMÉ GLOBAL
# ══════════════════════════════════════════════

def generer_resume_global(client, scan, cve_data, analyses_risques, analyses_cve):
    """Gemini génère le résumé exécutif global."""

    systeme  = scan.get("systeme", {})
    resume   = cve_data.get("resume", {})
    securite = scan.get("securite", {})
    defender = securite.get("defender", {})

    nb_crit     = resume.get("critique", 0)
    nb_elev     = resume.get("eleve", 0)
    nb_uniq     = resume.get("cve_uniques", 0)
    nb_ris_crit = resume.get("risques_critique", 0)
    nb_ris_elev = resume.get("risques_eleve", 0)

    # Problèmes critiques détectés
    problemes = []
    if not defender.get("protection_temps_reel"):
        problemes.append("Windows Defender désactivé")
    if scan.get("reseau", {}).get("parefeu_desactive"):
        problemes.append("Pare-feu désactivé")
    if not securite.get("lsass_protege"):
        problemes.append("LSASS non protégé")
    if scan.get("services", {}).get("spooler_actif"):
        problemes.append("Print Spooler actif (PrintNightmare)")
    if scan.get("reseau", {}).get("llmnr_active"):
        problemes.append("LLMNR activé (LLMNR Poisoning)")

    problemes_str = ", ".join(problemes[:5]) if problemes else "aucun problème critique majeur"

    prompt = f"""Tu es un expert RSSI. Génère un résumé exécutif d'audit de sécurité Windows.

DONNÉES DU SYSTÈME :
- Hostname : {systeme.get('hostname','PC')}
- OS : Windows {systeme.get('windows_version','11')} build {systeme.get('windows_build','')}
- CVE critiques : {nb_crit}
- CVE élevées : {nb_elev}
- CVE totales uniques : {nb_uniq}
- Risques config critiques : {nb_ris_crit}
- Risques config élevés : {nb_ris_elev}
- Problèmes principaux : {problemes_str}

Génère un JSON (sans markdown) :
{{
  "niveau_global": "CRITIQUE|ÉLEVÉ|MODÉRÉ|ACCEPTABLE",
  "score_securite": 0,
  "conseil": "Résumé exécutif en 2-3 phrases pour un responsable informatique",
  "points_critiques": ["point 1", "point 2", "point 3"],
  "actions_prioritaires": ["action urgente 1", "action urgente 2", "action urgente 3"]
}}

Le score_securite est sur 100 (0=très dangereux, 100=sécurisé).
Sois factuel et professionnel en français."""

    result = appeler_gemini_json(client, prompt, max_tokens=600)

    if result:
        return {
            "hostname":          systeme.get("hostname", "PC"),
            "date_analyse":      datetime.datetime.now().isoformat(),
            "niveau_global":     result.get("niveau_global", "CRITIQUE"),
            "score_securite":    result.get("score_securite", 20),
            "conseil":           result.get("conseil", ""),
            "points_critiques":  result.get("points_critiques", []),
            "actions_prioritaires": result.get("actions_prioritaires", []),
            "statistiques": {
                "cve_critiques":   nb_crit,
                "cve_elevees":     nb_elev,
                "cve_moyennes":    resume.get("moyen", 0),
                "total_cve":       nb_uniq,
                "risques_systeme": resume.get("risques_config", 0),
                "risques_critiques": nb_ris_crit,
            }
        }

    # Fallback
    score = max(0, 100 - nb_crit * 8 - nb_elev * 4 - nb_ris_crit * 6)
    if score < 40:   niveau = "CRITIQUE"
    elif score < 60: niveau = "ÉLEVÉ"
    elif score < 80: niveau = "MODÉRÉ"
    else:            niveau = "ACCEPTABLE"

    return {
        "hostname":      systeme.get("hostname", "PC"),
        "date_analyse":  datetime.datetime.now().isoformat(),
        "niveau_global": niveau,
        "score_securite": score,
        "conseil":       f"Le système présente {nb_crit} CVE critiques et {nb_ris_crit} risques de configuration critiques nécessitant une attention immédiate.",
        "points_critiques":     problemes,
        "actions_prioritaires": ["Activer Windows Defender", "Activer le pare-feu", "Protéger LSASS"],
        "statistiques": {
            "cve_critiques":   nb_crit,
            "cve_elevees":     nb_elev,
            "cve_moyennes":    resume.get("moyen", 0),
            "total_cve":       nb_uniq,
            "risques_systeme": resume.get("risques_config", 0),
            "risques_critiques": nb_ris_crit,
        }
    }


# ══════════════════════════════════════════════
#  POINT D'ENTRÉE PRINCIPAL
# ══════════════════════════════════════════════

def analyser_rapport():
    

    # Vérifier fichiers
    for path, nom in [(CVE_PATH, "cve_results.json"), (SCAN_PATH, "scan_complet.json")]:
        if not os.path.exists(path):
            
            return None

    with open(CVE_PATH,  "r", encoding="utf-8") as f:
        cve_data = json.load(f)
    with open(SCAN_PATH, "r", encoding="utf-8") as f:
        scan = json.load(f)

    systeme      = scan.get("systeme", {})
    risques_cfg  = cve_data.get("risques_config", [])
    categories   = cve_data.get("categories", [])


    client = init_gemini()
    if not client:
        print("  Gemini non disponible ")

    analyses_risques = analyser_risques_config(
        client, risques_cfg, systeme
    ) if client else [{
        "titre":          r.get("titre", ""),
        "niveau":         r.get("niveau", "ELEVE"),
        "explication":    r.get("detail", ""),
        "recommandation": r.get("detail", ""),
        "impact":         "",
    } for r in risques_cfg[:20]]


    time.sleep(2)

    # ── Étape 2 : Analyse CVE ──
    analyses_cve = analyser_cve_categories(
        client, categories, systeme
    ) if client else []
  

    time.sleep(2)

    # ── Étape 3 : Résumé global ──
    
    resume_global = generer_resume_global(
        client, scan, cve_data, analyses_risques, analyses_cve
    ) if client else {
        "hostname":      systeme.get("hostname", "PC"),
        "date_analyse":  datetime.datetime.now().isoformat(),
        "niveau_global": "CRITIQUE",
        "score_securite": 20,
        "conseil":       "Analyse automatique — Gemini non disponible",
        "points_critiques":     [],
        "actions_prioritaires": [],
        "statistiques":  cve_data.get("resume", {}),
    }
    

    # ── Assembler rapport complet ──
    rapport = {
        "date_generation":   datetime.datetime.now().isoformat(),
        "version":           "1.0",
        "resume_global":     resume_global,
        "analyses_risques":  analyses_risques,
        "analyses_cve":      analyses_cve,
        "donnees_brutes": {
            "cve_uniques":   cve_data.get("resume", {}).get("cve_uniques", 0),
            "categories":    len(categories),
            "risques_config": len(risques_cfg),
        }
    }

    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
    with open(RAPPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(rapport, f, indent=2, ensure_ascii=False)


    return rapport


if __name__ == "__main__":
    rapport = analyser_rapport()
    input("\nAppuie sur Entrée pour fermer...")