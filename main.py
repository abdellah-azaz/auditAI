# main.py — AuditAI v1.0
# Pipeline complet : Scanner → CVE Matcher → Ai Engine → Rapport HTML

import os
import sys
import json
import datetime
import importlib.util

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ══════════════════════════════════════════════
#  CHARGEMENT MODULES
# ══════════════════════════════════════════════

def charger_module(nom, fichier):
    chemin = os.path.join(BASE_DIR, "modules", fichier)
    if not os.path.exists(chemin):
        print(f"  ❌ Module introuvable : {chemin}")
        return None
    try:
        spec   = importlib.util.spec_from_file_location(nom, chemin)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        print(f"  ❌ Erreur chargement {fichier} : {e}")
        return None

# ══════════════════════════════════════════════
#  CHEMINS
# ══════════════════════════════════════════════

SCAN_PATH    = os.path.join(BASE_DIR, "data", "scan_complet.json")
CVE_PATH     = os.path.join(BASE_DIR, "data", "cve_results.json")
RAPPORT_PATH = os.path.join(BASE_DIR, "data", "rapport_complet.json")
HTML_PATH    = os.path.join(BASE_DIR, "data", "rapport_auditai.html")

os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)


# ══════════════════════════════════════════════
#  BANNIÈRE
# ══════════════════════════════════════════════



def afficher_etat():
    scan_ok    = os.path.exists(SCAN_PATH)
    cve_ok     = os.path.exists(CVE_PATH)
    rapport_ok = os.path.exists(RAPPORT_PATH)
    html_ok    = os.path.exists(HTML_PATH)


def afficher_menu():
    print("  ┌─────────────────────────────────────────────┐")
    print("  │  1. Audit complet (Scan + CVE + IA + HTML)  │")
    print("  │  2. Scan système uniquement                 │")
    print("  │  3. Matching CVE uniquement                 │")
    print("  │  4. Analyse IA uniquement                   │")
    print("  │  5. Générer rapport HTML uniquement         │")
    print("  │  6. Ouvrir rapport existant                 │")
    print("  │  7. Quitter                                 │")
    print("  └─────────────────────────────────────────────┘")
    print()


# ══════════════════════════════════════════════
#  ÉTAPES PIPELINE
# ══════════════════════════════════════════════

def etape_scan():
    scanner = charger_module("scanner", "Scanner.py")
    if not scanner:
        return False
    try:
        scan = scanner.lancer_scan()
        if scan:
            print("\n  ✅ Scan terminé !")
            return True
        return False
    except Exception as e:
        print(f"\n  ❌ Erreur scan : {e}")
        import traceback; traceback.print_exc()
        return False


def etape_cve():
    if not os.path.exists(SCAN_PATH):
        print("  ❌ Lancez d'abord le scan (option 2)")
        return False
    matcher = charger_module("cve_matcher", "cve_matcher.py")
    if not matcher:
        return False
    try:
        resultats = matcher.lancer_matching()
        if resultats:
            r = resultats.get("resume", {})
            print(f"\n  ✅ CVE uniques  : {r.get('cve_uniques', 0)}")
            print(f"  🔴 CRITIQUE     : {r.get('critique', 0)}")
            print(f"  🟠 ÉLEVÉ        : {r.get('eleve', 0)}")
            print(f"  ⚙️  Risques config : {r.get('risques_config', 0)}")
            return True
        return False
    except Exception as e:
        print(f"\n  ❌ Erreur CVE : {e}")
        import traceback; traceback.print_exc()
        return False


def etape_ia():
    print("\n  🤖 ANALYSE INTELLIGENTE (GEMINI)\n")
    if not os.path.exists(CVE_PATH):
        print("  ❌ Lancez d'abord le matching CVE (option 3)")
        return False
    ai_engine = charger_module("ai_engine", "Ai_engine.py")
    if not ai_engine:
        return False
    try:
        rapport = ai_engine.analyser_rapport()
        if rapport:
            rg = rapport.get("resume_global", {})
            print(f"\n  ✅ Niveau global   : {rg.get('niveau_global','?')}")
            print(f"  ✅ Score sécurité  : {rg.get('score_securite','?')}/100")
            return True
        return False
    except Exception as e:
        print(f"\n  ❌ Erreur IA : {e}")
        import traceback; traceback.print_exc()
        return False


def etape_rapport():
    print("\n  📄 GÉNÉRATION DU RAPPORT HTML\n")
    if not os.path.exists(CVE_PATH) or not os.path.exists(SCAN_PATH):
        print("  ❌ Données manquantes — lancez l'audit complet (option 1)")
        return False
    generator = charger_module("report_generator", "report_generator.py")
    if not generator:
        return False
    try:
        path = generator.generer_rapport()
        if path:
            print(f"\n  ✅ Rapport : {path}")
            return True
        return False
    except Exception as e:
        print(f"\n  ❌ Erreur rapport : {e}")
        import traceback; traceback.print_exc()
        return False


def ouvrir_rapport():
    if os.path.exists(HTML_PATH):
        import webbrowser
        webbrowser.open(f"file:///{HTML_PATH.replace(os.sep, '/')}")
        print(f"\n  🌐 Rapport ouvert : {HTML_PATH}")
    else:
        print("\n  ❌ Aucun rapport HTML trouvé")
        print("  Lancez d'abord l'audit complet (option 1)")


# ══════════════════════════════════════════════
#  PIPELINE COMPLET
# ══════════════════════════════════════════════

def audit_complet():
    print("\n" + "=" * 54)
    print("  AUDIT COMPLET — PIPELINE INTÉGRAL")
    print("=" * 54)
    debut = datetime.datetime.now()

    # Étape 1 — Scan
    print(f"\n  [1/4] SCAN SYSTÈME...")
    ok = etape_scan()
    if not ok:
        print("  ❌ Pipeline arrêté — scan échoué")
        return

    # Étape 2 — CVE
    print(f"\n  [2/4] MATCHING CVE...")
    ok = etape_cve()
    if not ok:
        print("  ❌ Pipeline arrêté — CVE matching échoué")
        return

    # Étape 3 — IA (optionnel)
    print(f"\n  [3/4] ANALYSE IA...")
    ok_ia = etape_ia()
    if not ok_ia:
        print("  ⚠️  Analyse IA ignorée — rapport sans IA")

    # Étape 4 — Rapport
    print(f"\n  [4/4] RAPPORT HTML...")
    etape_rapport()

    duree = int((datetime.datetime.now() - debut).total_seconds())
    print("\n" + "=" * 54)
    print(f"  ✅ AUDIT TERMINÉ en {duree // 60} min {duree % 60} sec")
    print(f"  📄 Rapport : {HTML_PATH}")
    print("=" * 54)


# ══════════════════════════════════════════════
#  MENU PRINCIPAL
# ══════════════════════════════════════════════

def main():
  
    while True:
        afficher_etat()
        afficher_menu()

        choix = input("  Votre choix (1-7) : ").strip()
        print()

        if choix == "1":
            audit_complet()

        elif choix == "2":
            etape_scan()

        elif choix == "3":
            etape_cve()

        elif choix == "4":
            etape_ia()

        elif choix == "5":
            etape_rapport()

        elif choix == "6":
            ouvrir_rapport()

        elif choix == "7":
            print("\n  Au revoir ! 👋\n")
            break

        else:
            print("  ⚠️  Choix invalide (1-7)")

        print()
        input("  ↩️  Appuie sur Entrée pour continuer...")
        print("\n" + "─" * 54 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Arrêt demandé. Au revoir !")
    except Exception as e:
        print(f"\n  ERREUR FATALE : {e}")
        import traceback
        traceback.print_exc()
    finally:
        input("\nAppuie sur Entrée pour fermer...")