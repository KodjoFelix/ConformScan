import os
import uuid
import markdown
from fpdf import FPDF

OUTPUT_DIR = "outputs"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def generate_report(scan_result: dict) -> str:
    ip = scan_result.get("scanned_ip", "unknown")
    open_ports = scan_result.get("open_ports", [])
    risk_score = scan_result.get("risk_score", 0)

    md_content = f"""# Rapport de Scan – {ip}

## Résumé
- **Adresse IP scannée** : `{ip}`
- **Ports ouverts détectés** : {', '.join(map(str, open_ports))}
- **Score de risque** : {risk_score} / 10

## Recommandations
{"- 🔴 Ports critiques détectés. Sécurisez les accès distants." if risk_score >= 5 else "- ✅ Aucun risque majeur détecté."}

## Détails techniques
{scan_result.get("status", "Aucun détail.")}
"""

    md_filename = f"rapport_{uuid.uuid4().hex}.md"
    md_path = os.path.join(OUTPUT_DIR, md_filename)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    pdf_path = convert_markdown_to_pdf(md_content, md_filename)

    # Construction du lien HTTP pour accéder au PDF (via FastAPI)
    pdf_url = f"http://127.0.0.1:8000/outputs/{os.path.basename(pdf_path)}"
    return pdf_url

def convert_markdown_to_pdf(md_content: str, md_filename: str) -> str:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)

    for line in md_content.split("\n"):
        safe_line = line.encode("latin-1", "replace").decode("latin-1")
        pdf.multi_cell(0, 10, safe_line)

    pdf_filename = md_filename.replace(".md", ".pdf")
    pdf_path = os.path.join(OUTPUT_DIR, pdf_filename)
    pdf.output(pdf_path)

    return pdf_path
