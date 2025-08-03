from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from datetime import datetime
from fastapi.responses import FileResponse
import os
from backend.auth import get_current_user
from backend.tcp_scan import scan_range, coerce_target_to_ip  # 🔁 correction ici

router = APIRouter()

class ScanRequest(BaseModel):
    target: str

# Port -> (Service, Recommandation, criticité)
RECO_RULES = {
    23:  ("Telnet", "Remplacer par SSH; chiffrer; désactiver si possible", "élevée"),
    3389:("RDP",    "Ne pas exposer sur Internet; VPN + MFA; limiter IP", "élevée"),
    445: ("SMB",    "Bloquer depuis Internet; limiter au LAN; signatures SMB", "élevée"),
    135: ("DCOM",   "Restreindre RPC/DCOM; filtrage réseau; durcissement hôte", "élevée"),
    21:  ("FTP",    "Passer à SFTP/FTPS; désactiver anonymes; chiffrer", "moyenne"),
    22:  ("SSH",    "Clés SSH fortes; MFA; désactiver password auth", "moyenne"),
    80:  ("HTTP",   "Forcer HTTPS (443); HSTS; redirection 301", "moyenne"),
    443: ("HTTPS",  "Vérifier certificat; TLS à jour; ciphers durcis", "faible"),
}
SEV_WEIGHT = {"faible": 1, "moyenne": 2, "élevée": 4}


def build_recommendations(open_ports):
    recos = []
    for p in open_ports:
        rule = RECO_RULES.get(p)
        if rule:
            service, text, sev = rule
            recos.append({"port": p, "service": service, "text": text, "severity": sev})
    return recos


def compute_risk_score(recos):
    score = sum(SEV_WEIGHT.get(r["severity"], 1) for r in recos)
    return min(score, 10)


def critical_ports_from(open_ports):
    crits = []
    for p in open_ports:
        rule = RECO_RULES.get(p)
        if rule and rule[2] == "élevée":
            crits.append(p)
    return crits


def generate_markdown_report(data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    ports = ", ".join(map(str, data["open_ports"]))
    if data["recommendations"]:
        recos_md = "\n".join(
            [f"- [{r['severity'].upper()}] Port {r['port']} ({r['service']}) : {r['text']}"
             for r in data["recommendations"]]
        )
    else:
        recos_md = "- (aucune)"

    content = f"""📄 Rapport de scan réseau – ConformScan
--------------------------------------

🕒 Date : {timestamp}
🌐 IP scannée : {data['scanned_ip']}
🔓 Ports ouverts : {ports}
🔥 Score de risque : {data['risk_score']}/10
✅ Statut : {data['status']}

📌 Recommandations (classées) :
{recos_md}

—
Généré par ConformScan
"""

    os.makedirs("reports", exist_ok=True)
    filename = f"rapport_{data['scanned_ip'].replace('.', '_')}.md"
    filepath = os.path.join("reports", filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath


@router.post("/scan")
def perform_scan(request: ScanRequest, user=Depends(get_current_user)):
    target = request.target.strip()
    ip = coerce_target_to_ip(target)  # 🔁 remplacement de la fonction manquante
    if not ip:
        raise HTTPException(status_code=400, detail="IP invalide")

    try:
        scan_data = scan_range(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur de scan interne: {e}")

    open_ports = scan_data.get("open_ports", [])
    recos = build_recommendations(open_ports)
    risk_score = compute_risk_score(recos)
    crit_ports = critical_ports_from(open_ports)

    result = {
        "scanned_ip": ip,
        "open_ports": open_ports,
        "status": "Scan terminé avec succès" if open_ports else "Aucun port détecté",
        "risk_score": risk_score,
        "recommendations": recos,
        "critical_ports": crit_ports,
    }

    try:
        generate_markdown_report(result)
    except Exception as e:
        print("Erreur génération rapport:", e)

    return {
        **result,
        "report_link": f"/download?ip={ip}"
    }


@router.get("/download")
def download_report(ip: str, user=Depends(get_current_user)):
    filename = f"rapport_{ip.replace('.', '_')}.md"
    path = os.path.join("reports", filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Rapport non trouvé")
    return FileResponse(path, media_type="text/markdown", filename=filename)
