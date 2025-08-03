from fastapi import FastAPI, Form, Header, HTTPException, Body
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
import uuid
import json
import random

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = os.path.join(os.path.dirname(__file__), '..', 'index.html')
    with open(index_path, encoding="utf-8") as f:
        return f.read()

def get_user(username):
    with open(os.path.join(os.path.dirname(__file__), '..', 'users.json'), encoding='utf-8') as f:
        users = json.load(f)
    for user in users:
        if user["username"] == username:
            return user
    return None

def get_current_user_role(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        return None, None
    token = authorization.split(" ", 1)[1]
    if ':' not in token:
        return None, None
    username, role = token.split(':', 1)
    return username, role

def get_user_by_token(authorization):
    username, role = get_current_user_role(authorization)
    if not username:
        return None
    with open(os.path.join(os.path.dirname(__file__), '..', 'users.json'), encoding='utf-8') as f:
        users = json.load(f)
    for user in users:
        if user["username"] == username:
            return user
    return None

@app.post("/register")
async def register(
    username: str = Body(...),
    password: str = Body(...)
):
    users_path = os.path.join(os.path.dirname(__file__), '..', 'users.json')
    with open(users_path, encoding='utf-8') as f:
        users = json.load(f)
    if any(u["username"] == username for u in users):
        raise HTTPException(status_code=400, detail="Utilisateur déjà existant")
    new_user = {
        "username": username,
        "password": password,
        "role": "user",
        "subscription": "inactive"
    }
    users.append(new_user)
    with open(users_path, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)
    return {"message": "Inscription réussie, vous pouvez vous connecter."}

@app.post("/token")
async def token(
    username: str = Form(...),
    password: str = Form(...),
    grant_type: str = Form(...)
):
    user = get_user(username)
    if user and user["password"] == password:
        return {"access_token": f"{username}:{user['role']}"}
    return {"detail": "Login incorrect"}, 401

class ScanRequest(BaseModel):
    target: Optional[str] = None
    ip_range: Optional[str] = None

IMPORTANT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5060, 5900, 8080, 8443, 10000
]

PORT_RECOMMENDATIONS = {
    21:  ("FTP", "moyenne", "Désactiver FTP ou basculer vers SFTP/FTPS pour éviter la fuite de données non chiffrées."),
    22:  ("SSH", "élevée", "Restreindre SSH par pare-feu, activer l’authentification forte, surveiller les accès."),
    23:  ("Telnet", "élevée", "Désactiver Telnet, non chiffré et obsolète."),
    25:  ("SMTP", "moyenne", "Limiter l’accès SMTP, surveiller le spam et le relais non autorisé."),
    53:  ("DNS", "moyenne", "Filtrer DNS vers l’extérieur, surveiller les tentatives d’exfiltration."),
    80:  ("HTTP", "moyenne", "Éviter HTTP ouvert sur Internet, passer à HTTPS, maintenir à jour."),
    110: ("POP3", "moyenne", "Utiliser POP3S, éviter les mots de passe en clair."),
    135: ("DCOM/RPC", "élevée", "Limiter l’accès RPC/DCOM aux réseaux internes, filtrer les ports."),
    139: ("NetBIOS", "élevée", "Désactiver ou restreindre NetBIOS au LAN uniquement."),
    143: ("IMAP", "moyenne", "Basculer vers IMAPS, éviter l’exposition sur Internet."),
    389: ("LDAP", "élevée", "Passer à LDAPS (chiffré), limiter l’accès, surveiller l’annuaire."),
    443: ("HTTPS", "faible", "Vérifier le certificat SSL, sécuriser les applications web."),
    445: ("SMB", "élevée", "Bloquer SMB/445 sur Internet, restreindre sur le LAN, désactiver SMBv1."),
    465: ("SMTPS", "faible", "Surveiller la configuration, maintenir à jour."),
    587: ("SMTP Submission", "faible", "Limiter et surveiller les usages externes."),
    993: ("IMAPS", "faible", "Surveiller la sécurité des comptes."),
    995: ("POP3S", "faible", "Surveiller la sécurité des comptes."),
    1433:("SQL Server", "élevée", "Restreindre SQL Server à l’interne, changer les mots de passe par défaut."),
    1521:("Oracle DB", "élevée", "Restreindre Oracle à l’interne, changer les mots de passe par défaut."),
    1723:("PPTP VPN", "élevée", "Remplacer PPTP par un VPN plus sécurisé (OpenVPN, IPsec)."),
    3306:("MySQL/MariaDB", "élevée", "Bloquer MySQL sur Internet, restreindre au LAN, changer les mots de passe par défaut."),
    3389:("RDP", "élevée", "Bloquer RDP sur Internet, limiter via VPN, activer MFA, surveiller les connexions."),
    5060:("SIP VoIP", "moyenne", "Limiter à l’interne, surveiller les usages frauduleux."),
    5900:("VNC", "élevée", "Bloquer sur Internet, restreindre, activer l’authentification forte."),
    8080:("HTTP Alt", "moyenne", "Vérifier le service exposé, sécuriser comme HTTP/HTTPS principal."),
    8443:("HTTPS Alt", "faible", "Vérifier le service exposé, sécuriser comme HTTPS principal."),
    10000:("Webmin/Admin Panels", "élevée", "Restreindre l’accès, activer MFA, ne pas exposer à Internet.")
}

def generate_recommendations(open_ports):
    recos = []
    for port in open_ports:
        if port in PORT_RECOMMENDATIONS:
            service, severity, text = PORT_RECOMMENDATIONS[port]
        else:
            service, severity, text = f"Port {port}", "faible", "Service inconnu : vérifier la nécessité et la sécurité."
        recos.append({
            "port": port,
            "service": service,
            "severity": severity,
            "text": text
        })
    return recos

def generate_pdf_report(scan_data, pdf_path):
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    y = height - 40
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(width / 2, y, "Rapport de Scan Réseau")
    c.setFont("Helvetica", 12)
    y -= 40
    c.drawString(50, y, f"IP scannée : {scan_data['scanned_ip']}")
    y -= 20
    c.drawString(50, y, f"Ports ouverts : {', '.join(map(str, scan_data['open_ports']))}")
    y -= 20
    c.drawString(50, y, f"Score de risque : {scan_data['risk_score']}")
    y -= 20
    c.drawString(50, y, f"Statut : {scan_data['status']}")
    y -= 30
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Recommandations :")
    y -= 20
    c.setFont("Helvetica", 11)
    for reco in scan_data["recommendations"]:
        if y < 80:
            c.showPage()
            y = height - 40
        txt = f"- Port {reco['port']} ({reco['service']}) [{reco['severity']}] : {reco['text']}"
        c.drawString(60, y, txt)
        y -= 18
    c.save()

def generate_pdf_report_multi(results_list, pdf_path):
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    y = height - 40
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(width / 2, y, "Rapport de Scan Réseau – Plage d’IP")
    y -= 40

    for res in results_list:
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"IP scannée : {res['scanned_ip']}")
        y -= 18
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Ports ouverts : {', '.join(map(str, res['open_ports']))}")
        y -= 16
        c.drawString(50, y, f"Score de risque : {res['risk_score']}")
        y -= 16
        c.drawString(50, y, f"Statut : {res['status']}")
        y -= 20
        c.setFont("Helvetica-Bold", 11)
        c.drawString(60, y, "Recommandations :")
        y -= 16
        c.setFont("Helvetica", 10)
        for reco in res["recommendations"]:
            if y < 80:
                c.showPage()
                y = height - 40
            txt = f"- Port {reco['port']} ({reco['service']}) [{reco['severity']}] : {reco['text']}"
            c.drawString(70, y, txt)
            y -= 13
        y -= 18
        if y < 120:
            c.showPage()
            y = height - 40
    c.save()

def random_open_ports():
    # Simule entre 3 et 7 ports ouverts parmi la liste importante
    return sorted(random.sample(IMPORTANT_PORTS, random.randint(3, 7)))

@app.post("/scan")
async def scan(request: ScanRequest, authorization: str = Header(None)):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Non autorisé")

    # ---- Plage d'IP ----
    if request.ip_range:
        try:
            start_ip, end_ip = request.ip_range.split('-')
            def ip2int(ip): return sum(int(octet) << (8 * (3-i)) for i, octet in enumerate(ip.split('.')))
            def int2ip(i): return '.'.join(str((i >> (8 * (3-n))) & 0xFF) for n in range(4))
            ips = [int2ip(i) for i in range(ip2int(start_ip), ip2int(end_ip)+1)]
        except:
            raise HTTPException(status_code=400, detail="Format de plage IP incorrect")

        result = []
        for ip in ips:
            open_ports = random_open_ports()
            recommendations = generate_recommendations(open_ports)
            criticity_score = sum(2 if r["severity"] == "élevée" else 1 for r in recommendations)
            status = "Critique" if criticity_score >= 10 else "Moyen" if criticity_score >= 4 else "Faible"
            data = {
                "scanned_ip": ip,
                "open_ports": open_ports,
                "critical_ports": [r["port"] for r in recommendations if r["severity"] == "élevée"],
                "risk_score": criticity_score,
                "status": status,
                "recommendations": recommendations
            }
            result.append(data)

        pdf_filename = f"rapport_plage_{uuid.uuid4().hex}.pdf"
        pdf_path = os.path.join(os.path.dirname(__file__), '..', pdf_filename)
        generate_pdf_report_multi(result, pdf_path)

        return {
            "plage_results": result,
            "report_link": f"/{pdf_filename}"
        }

    # ---- Scan IP unique ----
    open_ports = random_open_ports()
    recommendations = generate_recommendations(open_ports)
    criticity_score = sum(2 if r["severity"] == "élevée" else 1 for r in recommendations)
    status = "Critique" if criticity_score >= 10 else "Moyen" if criticity_score >= 4 else "Faible"
    result = {
        "scanned_ip": request.target or "unknown",
        "open_ports": open_ports,
        "critical_ports": [r["port"] for r in recommendations if r["severity"] == "élevée"],
        "risk_score": criticity_score,
        "status": status,
        "recommendations": recommendations
    }

    pdf_filename = f"rapport_{uuid.uuid4().hex}.pdf"
    pdf_path = os.path.join(os.path.dirname(__file__), '..', pdf_filename)
    generate_pdf_report(result, pdf_path)

    result["report_link"] = f"/{pdf_filename}"
    return result

@app.get("/{pdf_file}")
async def get_pdf(pdf_file: str):
    if pdf_file.endswith(".pdf"):
        pdf_path = os.path.join(os.path.dirname(__file__), '..', pdf_file)
        if not os.path.exists(pdf_path):
            raise HTTPException(status_code=404, detail="Fichier PDF non trouvé")
        return FileResponse(pdf_path, media_type="application/pdf", filename=pdf_file)
    raise HTTPException(status_code=404, detail="Fichier non trouvé")

@app.get("/admin/only")
async def admin_only(authorization: str = Header(None)):
    username, role = get_current_user_role(authorization)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs")
    return {"message": f"Bravo {username}, vous êtes admin !"}
