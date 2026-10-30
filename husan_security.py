
import os
import re
import io
import json
import base64
import socket
import hashlib
import ipaddress
import zipfile
import requests

from flask import Flask, request, render_template_string
from urllib.parse import urlparse

app = Flask(__name__)

# =====================================================
# 1. UMUMIY SOZLAMALAR
# =====================================================

MAX_SIZE = 20 * 1024 * 1024
TIMEOUT = 10

app.config["MAX_CONTENT_LENGTH"] = MAX_SIZE

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

VT_BASE = "https://www.virustotal.com/api/v3"

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "password",
    "wallet", "banking", "secure", "update",
    "signin", "confirm", "authenticate"
]

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd",
    ".scr", ".ps1", ".msi", ".apk"
}


# =====================================================
# 2. YORDAMCHI FUNKSIYALAR
# =====================================================

def risk_result(score, evidence, unknown=False):
    if unknown:
        level = "NOMA'LUM"
        recommendation = (
            "Tekshiruv uchun yetarli ma'lumot olinmadi. "
            "Obyektni hozircha xavfsiz deb hisoblamang."
        )
    elif score >= 60:
        level = "YUQORI"
        recommendation = (
            "Obyekt bilan ishlashni to'xtating. "
            "Havolani ochmang, faylni ishga tushirmang."
        )
    elif score >= 25:
        level = "O'RTA"
        recommendation = (
            "Obyektni ehtiyotkorlik bilan tekshiring. "
            "Shaxsiy ma'lumotlarni kiritmang."
        )
    else:
        level = "PAST"
        recommendation = (
            "Tekshirilgan indikatorlarda jiddiy xavf topilmadi. "
            "Bu mutlaq xavfsizlik kafolati emas."
        )

    return {
        "level": level,
        "score": min(score, 100),
        "evidence": evidence,
        "recommendation": recommendation
    }


def normalize_domain(value):
    value = value.strip()

    if "://" in value:
        parsed = urlparse(value)
        domain = parsed.hostname or ""
    else:
        domain = value.split("/")[0].split(":")[0]

    domain = domain.rstrip(".").lower()

    if not domain or len(domain) > 253:
        raise ValueError("Domen formati noto'g'ri.")

    if any(ch.isspace() for ch in domain):
        raise ValueError("Domen ichida bo'sh joy mavjud.")

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Domen kodlash xatosi.")

    if not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
        domain
    ):
        raise ValueError("Domen nomi noto'g'ri.")

    return domain


def dns_lookup(domain):
    result = {}

    try:
        records = socket.getaddrinfo(
            domain, None, type=socket.SOCK_STREAM
        )
        result["IP manzillar"] = sorted({
            item[4][0] for item in records
        })
    except (socket.gaierror, OSError):
        result["IP manzillar"] = []

    # Standart kutubxona orqali qo'shimcha DNS yozuvlarini
    # aniqlash uchun DNS serverga alohida kutubxona kerak.
    result["MX"] = "Bu versiyada alohida DNS kutubxonasi ulanmagan."
    result["NS"] = "Bu versiyada alohida DNS kutubxonasi ulanmagan."

    return result


# =====================================================
# 3. VIRUSTOTAL INTEGRATSIYASI
# =====================================================

def vt_request(endpoint):
    if not VT_API_KEY:
        return {
            "status": "unavailable",
            "message": "VirusTotal API kaliti sozlanmagan."
        }

    try:
        response = requests.get(
            VT_BASE + endpoint,
            headers={"x-apikey": VT_API_KEY},
            timeout=TIMEOUT
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": "VirusTotal bazasida mavjud hisobot topilmadi."
            }

        if response.status_code == 429:
            return {
                "status": "unavailable",
                "message": "VirusTotal so'rov chegarasi tugadi."
            }

        response.raise_for_status()

        return {
            "status": "success",
            "data": response.json()
        }

    except requests.RequestException:
        return {
            "status": "unavailable",
            "message": "VirusTotal bilan aloqa amalga oshmadi."
        }


def vt_analysis(endpoint):
    result = vt_request(endpoint)

    if result["status"] != "success":
        return result

    stats = (
        result["data"]
        .get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    return {
        "status": "success",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "stats": stats
    }


def vt_url_lookup(url):
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")

    return vt_analysis("/urls/" + url_id)


def vt_domain_lookup(domain):
    return vt_analysis("/domains/" + domain)


def vt_file_lookup(sha256):
    return vt_analysis("/files/" + sha256)


# =====================================================
# 4. GOOGLE SAFE BROWSING
# =====================================================

def google_safe_browsing(url):
    if not GSB_API_KEY:
        return {
            "status": "unavailable",
            "message": "Google Safe Browsing API kaliti sozlanmagan."
        }

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        "?key=" + GSB_API_KEY
    )

    payload = {
        "client": {
            "clientId": "husan-security",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=TIMEOUT
        )
        response.raise_for_status()

        data = response.json()

        return {
            "status": "success",
            "matches": data.get("matches", [])
        }

    except requests.RequestException:
        return {
            "status": "unavailable",
            "message": "Google Safe Browsing bilan aloqa amalga oshmadi."
        }


# =====================================================
# 5. URL TAHLILI
# =====================================================

def analyze_url(value, consent_vt=False, consent_gsb=False):
    evidence = []
    score = 0
    threat_types = []

    try:
        parsed = urlparse(value)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL faqat HTTP yoki HTTPS bo'lishi kerak.")

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("URL domeni aniqlanmadi.")

        if parsed.username or parsed.password or "@" in parsed.netloc:
            evidence.append(
                "URL ichida foydalanuvchini chalg'itishi mumkin "
                "bo'lgan @ belgisi mavjud."
            )
            score += 30
            threat_types.append("Spoofing ehtimoli")

        if parsed.scheme != "https":
            evidence.append("HTTPS protokoli ishlatilmayapti.")
            score += 10

        if len(value) > 100:
            evidence.append("URL uzunligi 100 belgidan oshgan.")
            score += 10

        if hostname.startswith("xn--") or ".xn--" in hostname:
            evidence.append("Domen Punycode formatida.")
            score += 20
            threat_types.append("Typosquatting ehtimoli")

        try:
            ipaddress.ip_address(hostname)
            evidence.append("URL domen o'rniga to'g'ridan-to'g'ri IP ishlatmoqda.")
            score += 20
            threat_types.append("Shubhali manzil")
        except ValueError:
            pass

        lowered = value.lower()

        found_words = [
            word for word in SUSPICIOUS_WORDS
            if word in lowered
        ]

        if found_words:
            evidence.append(
                "Shubhali kalit so'zlar: " + ", ".join(found_words)
            )
            score += min(20, len(found_words) * 5)
            threat_types.append("Phishing ehtimoli")

        if consent_gsb:
            gsb = google_safe_browsing(value)

            if gsb["status"] == "success":
                matches = gsb["matches"]

                if matches:
                    for match in matches:
                        threat = match.get(
                            "threatType", "Noma'lum tahdid"
                        )
                        evidence.append(
                            "Google Safe Browsing aniqladi: " + threat
                        )
                        threat_types.append(threat)

                    score = max(score, 80)
                else:
                    evidence.append(
                        "Google Safe Browsing ma'lum xavfli ro'yxatda "
                        "moslik topmadi."
                    )
            else:
                evidence.append(gsb["message"])

        if consent_vt:
            vt = vt_url_lookup(value)

            if vt["status"] == "success":
                malicious = vt["malicious"]
                suspicious = vt["suspicious"]

                evidence.append(
                    "VirusTotal: zararli aniqlashlar = "
                    + str(malicious)
                    + ", shubhali = " + str(suspicious)
                )

                if malicious:
                    score = max(score, 80)
                    threat_types.append("Malware yoki phishing indikatori")
                elif suspicious:
                    score = max(score, 40)
                    threat_types.append("Shubhali URL reputatsiyasi")

            else:
                evidence.append(vt["message"])

        if not evidence:
            evidence.append(
                "Mahalliy tekshiruvda shubhali indikator topilmadi."
            )

        report = risk_result(score, evidence)
        report["threat_types"] = sorted(set(threat_types))
        report["source"] = "Mahalliy tahlil"

        return report

    except ValueError as error:
        return risk_result(
            0,
            ["URL xatosi: " + str(error)],
            unknown=True
        )


# =====================================================
# 6. DOMEN TAHLILI
# =====================================================

def analyze_domain(value, consent_vt=False):
    evidence = []
    score = 0
    threat_types = []

    try:
        domain = normalize_domain(value)

        evidence.append("Domen formati to'g'ri.")
        dns = dns_lookup(domain)

        if dns["IP manzillar"]:
            evidence.append(
                "Aniqlangan IP manzillar: "
                + ", ".join(dns["IP manzillar"])
            )
        else:
            evidence.append("DNS orqali IP manzil aniqlanmadi.")
            score += 10

        if domain.startswith("xn--") or ".xn--" in domain:
            evidence.append("Domen Punycode formatida.")
            score += 20
            threat_types.append("Typosquatting ehtimoli")

        words = [
            word for word in SUSPICIOUS_WORDS
            if word in domain
        ]

        if words:
            evidence.append(
                "Domen tarkibida shubhali so'zlar mavjud: "
                + ", ".join(words)
            )
            score += 15
            threat_types.append("Phishing ehtimoli")

        if consent_vt:
            vt = vt_domain_lookup(domain)

            if vt["status"] == "success":
                evidence.append(
                    "VirusTotal: zararli aniqlashlar = "
                    + str(vt["malicious"])
                    + ", shubhali = " + str(vt["suspicious"])
                )

                if vt["malicious"]:
                    score = max(score, 80)
                    threat_types.append("Zararli domen indikatori")
                elif vt["suspicious"]:
                    score = max(score, 40)
                    threat_types.append("Shubhali domen reputatsiyasi")
            else:
                evidence.append(vt["message"])

        report = risk_result(score, evidence)
        report["domain"] = domain
        report["dns"] = dns
        report["threat_types"] = sorted(set(threat_types))
        report["source"] = "DNS va mahalliy tahlil"

        return report

    except ValueError as error:
        return risk_result(
            0,
            ["Domen xatosi: " + str(error)],
            unknown=True
        )


# =====================================================
# 7. FAYL VA APK TAHLILI
# =====================================================

def analyze_file(uploaded, consent_vt=False):
    if not uploaded or not uploaded.filename:
        return risk_result(
            0, ["Fayl tanlanmagan."], unknown=True
        )

    filename = os.path.basename(
        uploaded.filename.replace("\\", "/")
    )

    data = uploaded.stream.read(MAX_SIZE + 1)

    if len(data) > MAX_SIZE:
        return risk_result(
            0, ["Fayl 20 MB hajm chegarasidan katta."],
            unknown=True
        )

    evidence = []
    score = 0
    threat_types = []

    digest = hashlib.sha256(data).hexdigest()
    ext = os.path.splitext(filename)[1].lower()

    evidence.append("Fayl nomi: " + filename)
    evidence.append("Fayl hajmi: " + str(len(data)) + " bayt")
    evidence.append("SHA-256: " + digest)

    is_apk = False

    if data.startswith(b"MZ"):
        evidence.append("Windows PE fayliga xos MZ imzosi topildi.")

        if ext not in (".exe", ".dll", ".scr"):
            evidence.append(
                "Fayl kengaytmasi haqiqiy formatga mos kelmasligi mumkin."
            )
            score += 25

    elif data.startswith(b"PK"):
        evidence.append("ZIP arxiv imzosi topildi.")

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()

                has_manifest = any(
                    name == "AndroidManifest.xml"
                    for name in names
                )
                has_dex = any(
                    re.fullmatch(r"classes\d*\.dex", name)
                    for name in names
                )
                has_native = any(
                    name.endswith(".so")
                    for name in names
                )

                if has_manifest and has_dex:
                    is_apk = True
                    evidence.append(
                        "APK tuzilmasi aniqlandi: "
                        "AndroidManifest.xml va DEX fayli mavjud."
                    )

                    if has_native:
                        evidence.append(
                            "APK ichida native .so kutubxonasi mavjud."
                        )
                else:
                    evidence.append(
                        "ZIP arxivi topildi, ammo APK tuzilmasi "
                        "to'liq tasdiqlanmadi."
                    )

        except zipfile.BadZipFile:
            evidence.append("ZIP arxiv tuzilmasi noto'g'ri.")

    elif data.startswith(b"\x7fELF"):
        evidence.append("Linux ELF fayl imzosi topildi.")
    else:
        evidence.append(
            "Ma'lum asosiy fayl imzolari aniqlanmadi."
        )

    if ext in EXECUTABLE_EXTENSIONS:
        evidence.append(
            "Fayl bajariladigan dastur yoki skript kengaytmasiga ega."
        )

    if is_apk:
        threat_types.append("APK — Android ilovasi")
        evidence.append(
            "Android ruxsatlari ushbu versiyada to'liq dekodlanmagan."
        )

    if consent_vt:
        vt = vt_file_lookup(digest)

        if vt["status"] == "success":
            malicious = vt["malicious"]
            suspicious = vt["suspicious"]

            evidence.append(
                "VirusTotal: zararli aniqlashlar = "
                + str(malicious)
                + ", shubhali = " + str(suspicious)
            )

            if malicious:
                score = max(score, 90)
                threat_types.append("Malware indikatori")
            elif suspicious:
                score = max(score, 40)
                threat_types.append("Shubhali fayl reputatsiyasi")
        else:
            evidence.append(vt["message"])

    if not threat_types and ext in EXECUTABLE_EXTENSIONS:
        threat_types.append("Bajariladigan fayl")
        score += 10

    report = risk_result(score, evidence)
    report["sha256"] = digest
    report["threat_types"] = sorted(set(threat_types))
    report["file_type"] = "APK" if is_apk else ext or "Noma'lum"
    report["source"] = "Mahalliy fayl tahlili"
    report["file_uploaded_to_vt"] = False

    return report


# =====================================================
# 8. NATIJANI KO'RSATISH
# =====================================================

def format_report(report):
    lines = [
        "XAVF DARAJASI: " + report["level"],
        "XAVF BALLI: " + str(report["score"]) + "/100",
        "",
        "ANIQLANGAN XAVF TURLARI:"
    ]

    types = report.get("threat_types", [])

    if types:
        lines.extend(["- " + item for item in types])
    else:
        lines.append("- Aniq zararli tahdid turi tasdiqlanmadi.")

    lines.append("")
    lines.append("TEXNIK DALILLAR:")

    for item in report["evidence"]:
        lines.append("- " + item)

    lines.extend([
        "",
        "TAVSIYA:",
        report["recommendation"],
        "",
        "TAHLIL MANBASI: " + report.get(
            "source", "Mahalliy tahlil"
        )
    ])

    return "\n".join(lines)


# =====================================================
# 9. HTML INTERFEYS
# =====================================================

PAGE = """
<!DOCTYPE html>
<html lang="uz">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Husan Security</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1220;color:#e5edf8;font-family:Arial,sans-serif}
header{padding:28px;text-align:center;background:#111c30;border-bottom:1px solid #29466d}
header h1{color:#60a5fa;margin:0;font-size:32px}
header p{color:#aabbd2}
main{max-width:900px;margin:30px auto;padding:0 18px}
nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:22px}
button{padding:12px 18px;border:0;border-radius:8px;background:#2563eb;color:white;cursor:pointer}
button:hover{background:#1d4ed8}
section{background:#152238;border:1px solid #2a3d58;border-radius:12px;padding:24px}
h2{margin-top:0}
input{width:100%;padding:13px;margin:12px 0;background:#0b1220;color:white;border:1px solid #415573;border-radius:7px}
label{display:block;color:#cbd5e1;font-size:14px;margin:10px 0}
.result{white-space:pre-wrap;overflow-wrap:anywhere;margin-top:18px;padding:16px;border-radius:8px;background:#203652;border-left:4px solid #60a5fa;line-height:1.6}
.note{color:#aabbd2;font-size:13px;line-height:1.6}
footer{text-align:center;color:#91a4bf;padding:25px}
.hidden{display:none}
</style>
</head>
<body>
<header>
<h1>🛡️ Husan Security</h1>
<p>URL, domen va fayllarni dalillarga asoslangan xavfsizlik tahlili</p>
</header>

<main>
<nav>
<button type="button" onclick="showTab('url')">URL tahlili</button>
<button type="button" onclick="showTab('domain')">Domen tahlili</button>
<button type="button" onclick="showTab('file')">Fayl tahlili</button>
</nav>

<section id="url" class="{{ 'hidden' if kind and kind != 'url' else '' }}">
<h2>URL tahlili</h2>
<p>Tekshiriladigan havolani kiriting.</p>
<form method="post">
<input type="hidden" name="action" value="url">
<input name="url" maxlength="2048" placeholder="https://example.com" required>
<label><input type="checkbox" name="consent_vt" value="yes"> VirusTotal bilan tekshirishga roziman (URL tashqi xizmatga yuboriladi).</label>
<label><input type="checkbox" name="consent_gsb" value="yes"> Google Safe Browsing bilan tekshirishga roziman (URL Google'ga yuboriladi).</label>
<button type="submit">URL ni tekshirish</button>
</form>
{% if kind == 'url' %}<div class="result">{{ result }}</div>{% endif %}
</section>

<section id="domain" class="{{ 'hidden' if kind != 'domain' else '' }}">
<h2>Domen tahlili</h2>
<p>Domen nomini kiriting.</p>
<form method="post">
<input type="hidden" name="action" value="domain">
<input name="domain" maxlength="253" placeholder="example.com" required>
<label><input type="checkbox" name="consent_vt" value="yes"> VirusTotal bilan tekshirishga roziman (domen tashqi xizmatga yuboriladi).</label>
<button type="submit">Domenni tekshirish</button>
</form>
{% if kind == 'domain' %}<div class="result">{{ result }}</div>{% endif %}
</section>

<section id="file" class="{{ 'hidden' if kind != 'file' else '' }}">
<h2>Fayl va APK tahlili</h2>
<p>20 MB gacha fayl tanlang. Fayl ishga tushirilmaydi.</p>
<form method="post" enctype="multipart/form-data">
<input type="hidden" name="action" value="file">
<input type="file" name="file" required>
<label><input type="checkbox" name="consent_vt" value="yes"> VirusTotal'dan faqat SHA-256 xeshini qidirishga roziman. Faylning o'zi yuborilmaydi.</label>
<button type="submit">Faylni tahlil qilish</button>
</form>
{% if kind == 'file' %}<div class="result">{{ result }}</div>{% endif %}
</section>

<p class="note">
Eslatma: bu dastlabki xavfsizlik tahlili, to'liq antivirus emas.
Tashqi xizmat hisobotining yo'qligi xavfsizlik kafolati hisoblanmaydi.
Fayl VirusTotal'ga yuborilmaydi.
</p>
</main>

<footer>Husan Security</footer>

<script>
function showTab(id){
 document.querySelectorAll('main section').forEach(
  s=>s.classList.add('hidden')
 );
 document.getElementById(id).classList.remove('hidden');
}
</script>
</body>
</html>
"""


# =====================================================
# 10. FLASK YO'NALISHLARI
# =====================================================

@app.errorhandler(413)
def too_large(error):
    return "Fayl yoki so'rov 20 MB chegarasidan oshdi.", 413


@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    kind = ""

    if request.method == "POST":
        kind = request.form.get("action", "")
        consent_vt = request.form.get("consent_vt") == "yes"
        consent_gsb = request.form.get("consent_gsb") == "yes"

        if kind == "url":
            value = request.form.get("url", "").strip()

            if len(value) > 2048:
                report = risk_result(
                    0, ["URL juda uzun."], unknown=True
                )
            else:
                report = analyze_url(
                    value,
                    consent_vt=consent_vt,
                    consent_gsb=consent_gsb
                )

            result = format_report(report)

        elif kind == "domain":
            value = request.form.get("domain", "").strip()

            report = analyze_domain(
                value,
                consent_vt=consent_vt
            )

            result = format_report(report)

        elif kind == "file":
            uploaded = request.files.get("file")

            report = analyze_file(
                uploaded,
                consent_vt=consent_vt
            )

            result = format_report(report)

        else:
            result = "Noto'g'ri so'rov turi."

    return render_template_string(
        PAGE,
        result=result,
        kind=kind
    )


# =====================================================
# 11. DASTURNI ISHGA TUSHIRISH
# =====================================================

if __name__ == "__main__":
    print("Husan Security: http://127.0.0.1:5000")
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", 5000)),
        debug=False
    )
