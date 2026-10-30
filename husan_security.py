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
