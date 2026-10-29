
from flask import Flask, request, render_template_string
from urllib.parse import urlparse
import socket
import hashlib
import os

app = Flask(__name__)

# Fayl hajmi: 20 MB
MAX_SIZE = 20 * 1024 * 1024

# Butun HTTP so'rov hajmini ham cheklash
app.config["MAX_CONTENT_LENGTH"] = MAX_SIZE

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
.result{white-space:pre-wrap;overflow-wrap:anywhere;margin-top:18px;padding:16px;border-radius:8px;background:#203652;border-left:4px solid #60a5fa}
.note{color:#aabbd2;font-size:13px;line-height:1.6}
footer{text-align:center;color:#91a4bf;padding:25px}
.hidden{display:none}
</style>
</head>
<body>
<header>
<h1>🛡️ Husan Security</h1>
<p>URL, domen va fayllarni dastlabki xavfsizlik tekshiruvi</p>
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
<button type="submit">Domenni tekshirish</button>
</form>
{% if kind == 'domain' %}<div class="result">{{ result }}</div>{% endif %}
</section>

<section id="file" class="{{ 'hidden' if kind != 'file' else '' }}">
<h2>Fayl tahlili</h2>
<p>Kompyuteringizdan tekshiriladigan faylni tanlang (20 MB gacha).</p>
<form method="post" enctype="multipart/form-data">
<input type="hidden" name="action" value="file">
<input type="file" name="file" required>
<button type="submit">Faylni tahlil qilish</button>
</form>
{% if kind == 'file' %}<div class="result">{{ result }}</div>{% endif %}
</section>

<p class="note">
Eslatma: bu dastlabki tekshiruv vositasi. Natija sayt yoki faylning
mutlaqo xavfsizligini kafolatlamaydi. Fayl ishga tushirilmaydi.
Ushbu versiya tashqi antivirus bazasiga ulanmagan.
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

@app.errorhandler(413)
def too_large(error):
    return (
        "Fayl yoki so'rov hajmi 20 MB chegarasidan oshdi. "
        "Kichikroq fayl yuboring.",
        413
    )


@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    kind = ""

    if request.method == "POST":
        kind = request.form.get("action", "")

        if kind == "url":
            value = request.form.get("url", "").strip()

            if len(value) > 2048:
                result = "URL juda uzun."
            else:
                try:
                    parsed = urlparse(value)
                    hostname = parsed.hostname
                    warnings = []

                    if parsed.scheme not in ("http", "https") or not hostname:
                        result = (
                            "URL formati noto'g'ri. "
                            "http:// yoki https:// bilan boshlanadigan manzil kiriting."
                        )
                    else:
                        if parsed.scheme != "https":
                            warnings.append("HTTPS ishlatilmayapti.")
                        if "@" in parsed.netloc:
                            warnings.append("Manzilda @ belgisi mavjud.")
                        if len(value) > 100:
                            warnings.append("URL juda uzun.")
                        if hostname.startswith("xn--") or ".xn--" in hostname:
                            warnings.append("Domen Punycode formatida.")

                        if warnings:
                            result = (
                                "E'tibor talab qiladigan belgilar:\n- "
                                + "\n- ".join(warnings)
                            )
                        else:
                            result = (
                                "Oddiy tekshiruvda shubhali belgi topilmadi. "
                                "Bu xavfsizlik kafolati emas."
                            )

                except ValueError:
                    result = "URL formati noto'g'ri."

        elif kind == "domain":
            domain = request.form.get("domain", "").strip()

            try:
                if "://" in domain:
                    domain = urlparse(domain).hostname or ""
                else:
                    domain = domain.split("/")[0].split(":")[0]

                if (
                    not domain
                    or len(domain) > 253
                    or any(ch.isspace() for ch in domain)
                ):
                    raise ValueError("Domen noto'g'ri.")

                addresses = sorted({
                    item[4][0]
                    for item in socket.getaddrinfo(
                        domain, None, type=socket.SOCK_STREAM
                    )
                })

                result = (
                    "Domen: " + domain
                    + "\nIP manzillar:\n"
                    + "\n".join(addresses)
                )

            except (socket.gaierror, ValueError, OSError):
                result = (
                    "Domen aniqlanmadi yoki DNS so'rovi bajarilmadi."
                )

        elif kind == "file":
            uploaded = request.files.get("file")

            if not uploaded or not uploaded.filename:
                result = "Avval fayl tanlang."
            else:
                # Fayl nomini natijada xavfsizroq ko'rsatish
                filename = os.path.basename(
                    uploaded.filename.replace("\\", "/")
                )

                data = uploaded.stream.read(MAX_SIZE + 1)

                if len(data) > MAX_SIZE:
                    result = "Fayl 20 MB dan katta. Kichikroq fayl tanlang."
                else:
                    digest = hashlib.sha256(data).hexdigest()
                    ext = os.path.splitext(filename)[1].lower()
                    warnings = []

                    if ext in (
                        ".exe", ".dll", ".bat", ".cmd",
                        ".scr", ".ps1", ".apk"
                    ):
                        warnings.append(
                            "Bajariladigan dastur, skript yoki APK turi. "
                            "Bu belgi o'zi zararli ekanini isbotlamaydi."
                        )

                    if data.startswith(b"MZ"):
                        warnings.append(
                            "Windows PE fayliga xos MZ belgisi topildi."
                        )

                    if data.startswith(b"PK"):
                        warnings.append(
                            "ZIP asosidagi fayl belgisi topildi. "
                            "Bu APK kabi arxiv formatlarida ham uchrashi mumkin."
                        )

                    result = (
                        "Fayl nomi: " + filename
                        + "\nHajmi: " + str(len(data)) + " bayt"
                        + "\nSHA-256: " + digest
                        + "\nBelgilar: "
                        + (
                            "; ".join(warnings)
                            if warnings
                            else "Faqat asosiy belgilar tekshirildi."
                        )
                    )

        else:
            result = "Noto'g'ri so'rov turi."

    return render_template_string(
        PAGE, result=result, kind=kind
    )


if __name__ == "__main__":
    print("Husan Security: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
