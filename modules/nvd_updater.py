import urllib.request
import json
import sqlite3
import os
import datetime
import time
import calendar
import threading

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR    = os.path.join(BASE_DIR, "data", "nvd_db")
DB_PATH   = os.path.join(DB_DIR, "index.db")
UPD_PATH  = os.path.join(DB_DIR, "last_update.txt")
LOG_PATH  = os.path.join(DB_DIR, "update_log.txt")

PAR_PAGE  = 2000
ANNEE_MIN = 2020
DELAI     = 6       
JOURS_MAJ = 7       


# ══════════════════════════════════════════════
#  BASE DE DONNÉES
# ══════════════════════════════════════════════

def creer_base():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS cve (
            cve_id      TEXT PRIMARY KEY,
            annee       INTEGER,
            score       REAL,
            niveau      TEXT,
            description TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS cpe_cve (
            cpe_produit TEXT,
            cve_id      TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS progress (
            annee   INTEGER PRIMARY KEY,
            nb_cve  INTEGER,
            date_dl TEXT
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_cpe ON cpe_cve(cpe_produit)")
    conn.commit()
    conn.close()


def base_existe():
    if not os.path.exists(DB_PATH):
        return False
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT COUNT(*) FROM cve")
        nb   = c.fetchone()[0]
        conn.close()
        return nb > 1000
    except Exception:
        return False


def annee_telechargee(annee):
    if not os.path.exists(DB_PATH):
        return False
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT nb_cve FROM progress WHERE annee = ?", (annee,))
        row  = c.fetchone()
        conn.close()
        return row is not None and row[0] > 100
    except Exception:
        return False


def mise_a_jour_necessaire():
    if not base_existe():
        return True
    if not os.path.exists(UPD_PATH):
        return True
    try:
        with open(UPD_PATH) as f:
            derniere = datetime.datetime.fromisoformat(f.read().strip())
        return (utcnow() - derniere).days >= JOURS_MAJ
    except Exception:
        return True


def log(msg):
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(utcnow().strftime("%Y-%m-%d %H:%M UTC") + " | " + msg + "\n")
    except Exception:
        pass


# ══════════════════════════════════════════════
#  TÉLÉCHARGEMENT
# ══════════════════════════════════════════════

def niveau_depuis_score(score):
    if score >= 9.0:   return "CRITIQUE"
    elif score >= 7.0: return "ELEVE"
    elif score >= 4.0: return "MOYEN"
    else:              return "FAIBLE"


def telecharger_page(start_index, annee):
    maintenant = utcnow()
    if annee == maintenant.year:
        mois_fin = str(maintenant.month).zfill(2)
        jour_fin = str(calendar.monthrange(annee, maintenant.month)[1]).zfill(2)
        date_fin = f"{annee}-{mois_fin}-{jour_fin}T23:59:59.000"
    else:
        date_fin = f"{annee}-12-31T23:59:59.000"

    date_debut = f"{annee}-01-01T00:00:00.000"
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={date_debut}"
        f"&pubEndDate={date_fin}"
        f"&startIndex={start_index}"
        f"&resultsPerPage={PAR_PAGE}"
    )

    req = urllib.request.Request(url, headers={"User-Agent": "AuditAI/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def indexer_cves(data, conn):
    c  = conn.cursor()
    nb = 0

    for item in data.get("vulnerabilities", []):
        try:
            cve    = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            score   = 0.0
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", 0.0)
            elif "cvssMetricV30" in metrics:
                score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", 0.0)
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", 0.0)

            if score < 4.0:
                continue

            niveau    = niveau_depuis_score(score)
            annee_cve = int(cve_id.split("-")[1])

            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:300]
                    break

            c.execute(
                "INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?)",
                (cve_id, annee_cve, score, niveau, desc)
            )

            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable", False):
                            continue
                        cpe     = match.get("criteria", "")
                        parties = cpe.split(":")
                        if len(parties) >= 5:
                            cle = parties[3] + ":" + parties[4]
                            c.execute("INSERT INTO cpe_cve VALUES (?,?)", (cle, cve_id))
                            nb += 1
        except Exception:
            continue

    conn.commit()
    return nb


def telecharger_annee(annee, silencieux=False):
    if annee_telechargee(annee):
        return 0, 0

    creer_base()
    conn      = sqlite3.connect(DB_PATH)
    start     = 0
    total_cve = 0
    total_cpe = 0


    while True:
        try:

            data         = telecharger_page(start, annee)
            total_result = data.get("totalResults", 0)
            nb_cpe       = indexer_cves(data, conn)
            nb_cve       = len(data.get("vulnerabilities", []))
            total_cpe   += nb_cpe
            total_cve   += nb_cve

            start += PAR_PAGE
            if start >= total_result:
                break

            time.sleep(DELAI)

        except Exception as e:
            log(f"ERREUR annee {annee} : {str(e)}")
            time.sleep(15)
            break

    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO progress VALUES (?, ?, ?)",
        (annee, total_cve, utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    if not silencieux:
        taille = os.path.getsize(DB_PATH) // (1024 * 1024)
        print(f"    --> {total_cve} CVE / {taille} MB")

    log(f"Annee {annee} telechargee : {total_cve} CVE")
    return total_cve, total_cpe


# ══════════════════════════════════════════════
#  MAJ DELTA — CVE modifiées depuis dernière MAJ
# ══════════════════════════════════════════════

def mise_a_jour_delta(silencieux=False):
    creer_base()

    # UTC partout = synchronisé avec NVD
    maintenant = utcnow()
    fin        = maintenant.strftime("%Y-%m-%dT%H:%M:%S.000")

    if os.path.exists(UPD_PATH):
        with open(UPD_PATH) as f:
            debut = f.read().strip()
    else:
        debut = (maintenant - datetime.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")

    if not silencieux:
        print(f"  MAJ delta : {debut} → {fin}")

    log(f"Debut MAJ delta : {debut} → {fin}")

    start = 0
    conn  = sqlite3.connect(DB_PATH)
    total = 0

    while True:
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?lastModStartDate={debut}"
            f"&lastModEndDate={fin}"
            f"&startIndex={start}"
            f"&resultsPerPage={PAR_PAGE}"
        )

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AuditAI/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))

        except Exception as e:
            log(f"ERREUR delta : {str(e)}")
            break

        total_result = data.get("totalResults", 0)

        if total_result == 0:
            if not silencieux:
                print("  Aucune nouvelle CVE")
            break

        nb     = indexer_cves(data, conn)
        total += nb

        if not silencieux:
            print(f"  Page {start // PAR_PAGE + 1} : {nb} CVE")

        start += PAR_PAGE
        if start >= total_result:
            break

        time.sleep(DELAI)

    conn.close()

    # Sauvegarder en UTC après succès
    with open(UPD_PATH, "w") as f:
        f.write(fin)

    log(f"MAJ delta terminee : {total} CVE")

    if not silencieux:
        print(f"  MAJ delta terminee : {total} CVE ✅")


# ══════════════════════════════════════════════
#  API PUBLIQUE — utilisée par main.py
# ══════════════════════════════════════════════

def lancer_en_arriere_plan():
    """
    Appelé par main.py au démarrage.
    MAJ silencieuse en arrière-plan.
    Ne bloque pas l'utilisateur.
    """
    if not mise_a_jour_necessaire():
        return None

    thread = threading.Thread(
        target=mise_a_jour_delta,
        kwargs={"silencieux": True},
        daemon=True
    )
    thread.start()
    log("MAJ arriere-plan lancee")
    return thread


def get_statut():
    """Retourne le statut de la base pour l'interface."""
    if not base_existe():
        return "base_absente"
    if mise_a_jour_necessaire():
        return "maj_necessaire"
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT COUNT(*) FROM cve")
        nb   = c.fetchone()[0]
        conn.close()
        return f"ok_{nb}"
    except Exception:
        return "erreur"


# ══════════════════════════════════════════════
#  MENU PRINCIPAL
# ══════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "=" * 52)
    print("  AuditAI - Gestionnaire base NVD")
    print("  Mode : Sans cle API (standard)")
    print("=" * 52)

    print("\n  1 - Telecharger une annee specifique")
    print("  2 - Telecharger toutes les annees")
    print("  3 - Mise a jour delta (nouvelles CVE)")
    print("  4 - Statut de la base")
    print("  5 - Quitter\n")

    choix = input("  Votre choix (1/2/3/4/5) : ").strip()

    try:
        if choix == "1":
            annee_str = input(f"  Quelle annee ? ({ANNEE_MIN}-2026) : ").strip()
            annee = int(annee_str)
            if ANNEE_MIN <= annee <= 2026:
                creer_base()
                telecharger_annee(annee)
            else:
                print("  Annee invalide !")

        elif choix == "2":
            maintenant     = utcnow()
            annee_actuelle = maintenant.year
            print(f"\n  Telechargement {ANNEE_MIN} → {annee_actuelle}")
            print("  Reprise automatique si interruption !\n")
            creer_base()
            total = 0
            for annee in range(ANNEE_MIN, annee_actuelle + 1):
                nb, _ = telecharger_annee(annee)
                total += nb
            with open(UPD_PATH, "w") as f:
                f.write(maintenant.strftime("%Y-%m-%dT%H:%M:%S.000"))
            taille = os.path.getsize(DB_PATH) // (1024 * 1024)
            print(f"\n  TERMINE ! {total} CVE / {taille} MB ✅")

        elif choix == "3":
            mise_a_jour_delta()

        elif choix == "4":
            statut = get_statut()
            print(f"\n  Statut : {statut}")
            if os.path.exists(UPD_PATH):
                with open(UPD_PATH) as f:
                    print("  Derniere MAJ (UTC) : " + f.read().strip())
            if os.path.exists(DB_PATH):
                taille = os.path.getsize(DB_PATH) // (1024 * 1024)
                print(f"  Taille base : {taille} MB")

        elif choix == "5":
            print("  Au revoir !")

    except KeyboardInterrupt:
        print("\n\n  Arret demande.")
        print("  Donnees deja telechargees sauvegardees ! ✅")
    except Exception as e:
        print("ERREUR : " + str(e))
        import traceback
        traceback.print_exc()

    input("\nAppuie sur Entree pour fermer...")