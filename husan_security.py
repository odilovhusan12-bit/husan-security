
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

MAX_SIZE = 20 * 1024 * 1024
TIMEOUT = 10

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

    result["MX"] = "Bu versiyada alohida DNS kutubxonasi ulanmagan."
    result["NS"] = "Bu versiyada alohida DNS kutubxonasi ulanmagan."

    return result


# =====================================================
# 3. VIRUSTOTAL INTEGRATSIYASI
# =====================================================

def vt_request(endpoint):
    """VirusTotal API so'rovini bajaradi; maxfiy kalitni oshkor qilmaydi."""
    if not VT_API_KEY:
        return {
            "status": "unavailable",
            "message": "VirusTotal API kaliti server muhitida topilmadi."
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
                "message": (
                    "VirusTotal bazasida ushbu obyekt uchun hisobot topilmadi. "
                    "Bu obyekt xavfsizligini anglatmaydi."
                )
            }

        if response.status_code == 401:
            return {
                "status": "unavailable",
                "message": "VirusTotal API kaliti noto'g'ri yoki yaroqsiz (401)."
            }

        if response.status_code == 403:
            return {
                "status": "unavailable",
                "message": "VirusTotal API so'roviga ruxsat berilmadi (403)."
            }

        if response.status_code == 429:
            return {
                "status": "unavailable",
                "message": "VirusTotal so'rov chegarasi tugadi (429). Keyinroq urinib ko'ring."
            }

        response.raise_for_status()

        return {
            "status": "success",
            "data": response.json()
        }

    except requests.Timeout:
        return {
            "status": "unavailable",
            "message": "VirusTotal javobi belgilangan vaqtda kelmadi (timeout)."
        }

    except requests.RequestException:
        return {
            "status": "unavailable",
            "message": "VirusTotal bilan aloqa amalga oshmadi. Tarmoq yoki API holatini tekshiring."
        }

    except ValueError:
        return {
            "status": "unavailable",
            "message": "VirusTotal javobini o'qib bo'lmadi."
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

    return {
        "status": "success",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
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
    successful_checks = []
    attempted_checks = []

    try:
        parsed = urlparse(value)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL faqat HTTP yoki HTTPS bo'lishi kerak.")

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("URL domeni aniqlanmadi.")

        if parsed.username or parsed.password or "@" in parsed.netloc:
            evidence.append(
                "URL ichida foydalanuvchini chalg'itishi mumkin bo'lgan @ belgisi mavjud."
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

        found_words = [
            word for word in SUSPICIOUS_WORDS if word in value.lower()
        ]

        if found_words:
            evidence.append(
                "Shubhali kalit so'zlar: " + ", ".join(found_words)
            )
            score += min(20, len(found_words) * 5)
            threat_types.append("Phishing ehtimoli")

        # Google Safe Browsing
        if consent_gsb:
            attempted_checks.append("Google Safe Browsing")
            gsb = google_safe_browsing(value)

            if gsb["status"] == "success":
                successful_checks.append("Google Safe Browsing")
                matches = gsb.get("matches", [])

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
                        "Google Safe Browsing tekshiruvi bajarildi: "
                        "ma'lum xavfli ro'yxatda moslik topilmadi."
                    )
            else:
                evidence.append(
                    "Google Safe Browsing: " +
                    gsb.get("message", "Tekshiruv bajarilmadi.")
                )

        # VirusTotal
        if consent_vt:
            attempted_checks.append("VirusTotal")
            vt = vt_url_lookup(value)

            if vt["status"] == "success":
                successful_checks.append("VirusTotal")

                malicious = vt.get("malicious", 0)
                suspicious = vt.get("suspicious", 0)
                harmless = vt.get("harmless", 0)
                undetected = vt.get("undetected", 0)

                evidence.append(
                    "VirusTotal hisoboti olindi: zararli aniqlashlar = "
                    + str(malicious)
                    + ", shubhali = " + str(suspicious)
                    + ", harmless = " + str(harmless)
                    + ", aniqlanmagan = " + str(undetected) + "."
                )

                if malicious > 0:
                    score = max(score, 80)
                    threat_types.append(
                        "VirusTotal zararli URL indikatori"
                    )

                elif suspicious > 0:
                    score = max(score, 40)
                    threat_types.append(
                        "Shubhali URL reputatsiyasi"
                    )

                else:
                    evidence.append(
                        "VirusTotal hisobotida zararli yoki shubhali "
                        "aniqlash qayd etilmadi. Bu mutlaq xavfsizlik kafolati emas."
                    )

            else:
                evidence.append(
                    "VirusTotal: " +
                    vt.get("message", "Tashqi tekshiruv bajarilmadi.")
                )

        else:
            evidence.append(
                "VirusTotal tekshiruvi rozilik berilmagani sababli bajarilmadi."
            )

        if not evidence:
            evidence.append(
                "Mahalliy tekshiruvda shubhali indikator topilmadi."
            )

        unknown = score == 0 and not successful_checks

        report = risk_result(
            score,
            evidence,
            unknown=unknown
        )

        report["threat_types"] = sorted(set(threat_types))

        if successful_checks:
            report["source"] = (
                "Mahalliy tahlil + " + " + ".join(successful_checks)
            )
        else:
            report["source"] = (
                "Faqat mahalliy tahlil; tashqi reputatsiya tasdiqlanmadi"
            )

        report["external_checks"] = {
            "attempted": attempted_checks,
            "successful": successful_checks
        }

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
    successful_checks = []
    attempted_checks = []

    try:
        domain = normalize_domain(value)

        evidence.append("Domen formati to'g'ri.")

        dns = dns_lookup(domain)

        if dns["IP manzillar"]:
            evidence.append(
                "Aniqlangan IP manzillar: " +
                ", ".join(dns["IP manzillar"])
            )
        else:
            evidence.append("DNS orqali IP manzil aniqlanmadi.")

        if domain.startswith("xn--") or ".xn--" in domain:
            evidence.append("Domen Punycode formatida.")
            score += 20
            threat_types.append("Typosquatting ehtimoli")

        words = [
            word for word in SUSPICIOUS_WORDS if word in domain
        ]

        if words:
            evidence.append(
                "Domen tarkibida shubhali so'zlar mavjud: " +
                ", ".join(words)
            )
            score += 15
            threat_types.append("Phishing ehtimoli")

        if consent_vt:
            attempted_checks.append("VirusTotal")
            vt = vt_domain_lookup(domain)

            if vt["status"] == "success":
                successful_checks.append("VirusTotal")

                malicious = vt.get("malicious", 0)
                suspicious = vt.get("suspicious", 0)

                evidence.append(
                    "VirusTotal hisoboti olindi: zararli aniqlashlar = "
                    + str(malicious)
                    + ", shubhali = " + str(suspicious) + "."
                )

                if malicious > 0:
                    score = max(score, 80)
                    threat_types.append(
                        "VirusTotal zararli domen indikatori"
                    )

                elif suspicious > 0:
                    score = max(score, 40)
                    threat_types.append(
                        "Shubhali domen reputatsiyasi"
                    )

                else:
                    evidence.append(
                        "VirusTotal hisobotida zararli yoki shubhali "
                        "aniqlash qayd etilmadi; bu kafolat emas."
                    )

            else:
                evidence.append(
                    "VirusTotal: " +
                    vt.get("message", "Tekshiruv bajarilmadi.")
                )

        else:
            evidence.append(
                "VirusTotal tekshiruvi rozilik berilmagani sababli bajarilmadi."
            )

        unknown = score == 0 and not successful_checks

        report = risk_result(
            score,
            evidence,
            unknown=unknown
        )

        report["domain"] = domain
        report["dns"] = dns
        report["threat_types"] = sorted(set(threat_types))

        if successful_checks:
            report["source"] = (
                "DNS + mahalliy tahlil + " +
                " + ".join(successful_checks)
            )
        else:
            report["source"] = (
                "DNS va mahalliy tahlil; tashqi reputatsiya tasdiqlanmadi"
            )

        report["external_checks"] = {
            "attempted": attempted_checks,
            "successful": successful_checks
        }

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
            0,
            ["Fayl tanlanmagan."],
            unknown=True
        )

    filename = os.path.basename(
        uploaded.filename.replace("\\", "/")
    )

    data = uploaded.stream.read(MAX_SIZE + 1)

    if len(data) > MAX_SIZE:
        return risk_result(
            0,
            ["Fayl 20 MB hajm chegarasidan katta."],
            unknown=True
        )

    evidence = []
    score = 0
    threat_types = []
    successful_checks = []
    attempted_checks = []

    digest = hashlib.sha256(data).hexdigest()
    ext = os.path.splitext(filename)[1].lower()

    evidence.extend([
        "Fayl nomi: " + filename,
        "Fayl hajmi: " + str(len(data)) + " bayt",
        "SHA-256: " + digest
    ])

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

                has_manifest = "AndroidManifest.xml" in names
                has_dex = any(
                    re.fullmatch(r"classes\d*\.dex", name)
                    for name in names
                )
                has_native = any(
                    name.endswith(".so") for name in names
                )

                if has_manifest and has_dex:
                    is_apk = True

                    evidence.append(
                        "APK tuzilmasi aniqlandi: AndroidManifest.xml va DEX fayli mavjud."
                    )

                    if has_native:
                        evidence.append(
                            "APK ichida native .so kutubxonasi mavjud."
                        )

                else:
                    evidence.append(
                        "ZIP arxivi topildi, ammo APK tuzilmasi to'liq tasdiqlanmadi."
                    )

        except zipfile.BadZipFile:
            evidence.append("ZIP arxiv tuzilmasi noto'g'ri.")

    elif data.startswith(b"\x7fELF"):
        evidence.append("Linux ELF fayl imzosi topildi.")

    else:
        evidence.append("Ma'lum asosiy fayl imzolari aniqlanmadi.")

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
        attempted_checks.append("VirusTotal")
        vt = vt_file_lookup(digest)

        if vt["status"] == "success":
            successful_checks.append("VirusTotal")

            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)

            evidence.append(
                "VirusTotal hisoboti olindi: zararli aniqlashlar = "
                + str(malicious)
                + ", shubhali = " + str(suspicious) + "."
            )

            if malicious > 0:
                score = max(score, 90)
                threat_types.append(
                    "VirusTotal zararli fayl indikatori"
                )

            elif suspicious > 0:
                score = max(score, 40)
                threat_types.append(
                    "Shubhali fayl reputatsiyasi"
                )

            else:
                evidence.append(
                    "VirusTotal hisobotida zararli yoki shubhali "
                    "aniqlash qayd etilmadi; bu kafolat emas."
                )

        else:
            evidence.append(
                "VirusTotal: " +
                vt.get("message", "Tekshiruv bajarilmadi.")
            )

    else:
        evidence.append(
            "VirusTotal xesh qidiruvi rozilik berilmagani sababli bajarilmadi."
        )

    if ext in EXECUTABLE_EXTENSIONS:
        evidence.append(
            "Eslatma: kengaytma fayl bajarilishini bildiradi, "
            "ammo o'zi zararli ekanini isbotlamaydi."
        )

    unknown = score == 0 and not successful_checks

    report = risk_result(
        score,
        evidence,
        unknown=unknown
    )

    report["sha256"] = digest
    report["threat_types"] = sorted(set(threat_types))
    report["file_type"] = "APK" if is_apk else ext or "Noma'lum"

    if successful_checks:
        report["source"] = (
            "Mahalliy fayl tahlili + VirusTotal xesh hisoboti"
        )
    else:
        report["source"] = (
            "Faqat mahalliy fayl tahlili; tashqi reputatsiya tasdiqlanmadi"
        )

    report["external_checks"] = {
        "attempted": attempted_checks,
        "successful": successful_checks
    }

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
        lines.append(
            "- Aniq zararli tahdid turi tasdiqlanmadi."
        )

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
            "source",
            "Mahalliy tahlil"
        )
    ])

    checks = report.get("external_checks", {})
    attempted = checks.get("attempted", [])
    successful = checks.get("successful", [])

    if attempted:
        lines.extend(["", "TASHQI TEKSHIRUV:"])
        lines.append(
            "- So'ralgan: " + ", ".join(attempted)
        )
        lines.append(
            "- Muvaffaqiyatli: " +
            (", ".join(successful) if successful else "Hech biri")
        )

    return "\n".join(lines)
    # =====================================================
# 9. SAYTNING HTML INTERFEYSI
# =====================================================

PAGE = """
<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Husan Security</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #101827;
            color: white;
            margin: 0;
            padding: 30px;
        }
        .container {
            max-width: 850px;
            margin: auto;
        }
        .card {
            background: #1e293b;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 12px;
        }
        input, select, button {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            box-sizing: border-box;
            border-radius: 6px;
        }
        button {
            background: #2563eb;
            color: white;
            border: none;
            cursor: pointer;
        }
        pre {
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            line-height: 1.6;
        }
        label {
            display: block;
            margin: 12px 0;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <h1>HUSAN SECURITY</h1>
        <p>Havola, domen va fayllarni xavfsizlik bo‘yicha dastlabki tahlil qilish.</p>

        <form method="POST" enctype="multipart/form-data">
            <label>Tahlil turini tanlang:</label>
            <select name="mode" required>
                <option value="url">URL havolani tekshirish</option>
                <option value="domain">Domenni tekshirish</option>
                <option value="file">Fayl yoki APK tekshirish</option>
            </select>

            <label>URL yoki domen:</label>
            <input type="text" name="value"
                   placeholder="https://example.com">

            <label>Fayl yoki APK tanlang:</label>
            <input type="file" name="uploaded_file">

            <label>
                <input type="checkbox" name="consent_vt" value="yes">
                VirusTotal orqali tekshirishga roziman
            </label>

            <label>
                <input type="checkbox" name="consent_gsb" value="yes">
                Google Safe Browsing orqali tekshirishga roziman
            </label>

            <button type="submit">TAHLILNI BOSHLASH</button>
        </form>
    </div>

    {% if result %}
    <div class="card">
        <h2>TAHLIL NATIJASI</h2>
        <pre>{{ result }}</pre>
    </div>
    {% endif %}
</div>
</body>
</html>
"""


# =====================================================
# 10. FLASK SAHIFA YO'LLARI
# =====================================================

@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        mode = request.form.get("mode", "")
        value = request.form.get("value", "").strip()

        consent_vt = request.form.get("consent_vt") == "yes"
        consent_gsb = request.form.get("consent_gsb") == "yes"

        try:
            if mode == "url":
                report = analyze_url(
                    value,
                    consent_vt=consent_vt,
                    consent_gsb=consent_gsb
                )

            elif mode == "domain":
                report = analyze_domain(
                    value,
                    consent_vt=consent_vt
                )

            elif mode == "file":
                uploaded = request.files.get("uploaded_file")
                report = analyze_file(
                    uploaded,
                    consent_vt=consent_vt
                )

            else:
                report = risk_result(
                    0,
                    ["Tahlil turi noto'g'ri tanlangan."],
                    unknown=True
                )

            result = format_report(report)

        except Exception:
            result = (
                "Tahlil vaqtida kutilmagan xatolik yuz berdi. "
                "Kiritilgan ma'lumot va server loglarini tekshiring."
            )

    return render_template_string(PAGE, result=result)


@app.errorhandler(413)
def file_too_large(error):
    return "Fayl hajmi 20 MB dan oshmasligi kerak.", 413


if __name__ == "__main__":
    app.run(debug=False)
