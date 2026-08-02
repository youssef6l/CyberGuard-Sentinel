import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from flask import Flask, request, jsonify, render_template, send_file
from modules.static_analysis  import run_static_analysis
from modules.hashing           import calculate_sha256
from modules.virustotal        import check_hash_virustotal
from modules.behavior_engine   import run_behavior_analysis
from modules.report_generator  import generate_json_report, generate_pdf_report
from modules.sandbox           import run_sandbox_analysis
from modules.url_scanner       import scan_url
from modules.yara_scanner      import scan_file as yara_scan       # ← جديد
from modules.risk_score        import calculate_risk_score          # ← جديد
from modules.usb_scanner       import scan_usb_drives

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'exe'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ─────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


# ─────────────────────────────────────────────
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'لم يتم العثور على ملف في الطلب'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'لم يتم اختيار ملف'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'مسموح فقط بملفات .exe'}), 400

    filename = file.filename.replace(" ", "_")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        file.save(filepath)
    except Exception as e:
        return jsonify({'error': f'Failed to save file: {str(e)}'}), 500

    # ── 1. Hashing ──────────────────────────────────────────────
    file_hash = calculate_sha256(filepath)

    # ── 2. Static Analysis ──────────────────────────────────────
    static_results = run_static_analysis(filepath)

    # ── 3. VirusTotal ───────────────────────────────────────────
    vt_result = check_hash_virustotal(file_hash)

    # ── 4. YARA Scan ────────────────────────────────────────────  ← جديد
    yara_result = yara_scan(filepath)

    # ── 5. Sandbox ──────────────────────────────────────────────
    sandbox_results  = run_sandbox_analysis(filepath, filename)
    csv_log_path     = sandbox_results.get('csv_log_path', None)

    # ── 6. Behavior Analysis ────────────────────────────────────
    behavior_results = run_behavior_analysis(static_results, vt_result, csv_log_path)
    behavior_results['sandbox_status'] = (
        "Success" if sandbox_results.get('success') else "Failed"
    )

    # ── 7. Risk Score ───────────────────────────────────────────  ← جديد
    risk = calculate_risk_score(
        vt_result       = vt_result,
        yara_result     = yara_result,
        static_result   = static_results,
        behavior_result = behavior_results,
        sandbox_result  = sandbox_results,
    )

    # ── 8. Reports ──────────────────────────────────────────────
    json_report = generate_json_report(
        filename, file_hash, vt_result, static_results, behavior_results,
        yara_result=yara_result,
        risk=risk
    )

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{filename}_report.pdf')
    generate_pdf_report(
        filename, file_hash, vt_result, static_results, behavior_results, pdf_path,
        yara_result=yara_result,
        risk=risk
    )

    # ── Response ─────────────────────────────────────────────────
    return jsonify({
        'message'          : 'Advanced Analysis Completed 🛡️',
        'filename'         : filename,
        'sha256'           : file_hash,
        'virustotal'       : vt_result,
        'yara'             : yara_result,        # ← جديد
        'risk_score'       : risk,               # ← جديد
        'static_analysis'  : static_results,
        'sandbox'          : sandbox_results,
        'behavior_analysis': behavior_results,
        'report'           : json_report,
        'pdf_report'       : pdf_path
    })


# ─────────────────────────────────────────────
@app.route('/download-report')
def download_report():
    path = request.args.get('path')
    if path and os.path.exists(path):
        real_path   = os.path.realpath(path)
        uploads_dir = os.path.realpath(app.config['UPLOAD_FOLDER'])
        if not real_path.startswith(uploads_dir):
            return jsonify({'error': 'Access denied'}), 403
        return send_file(real_path, as_attachment=True)
    return jsonify({'error': 'Report not found'}), 404


# ─────────────────────────────────────────────
@app.route('/scan-url', methods=['POST'])
def scan_url_route():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400

    url = data['url'].strip()
    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400

    result = scan_url(url)
    return jsonify(result)

@app.route('/scan-usb', methods=['POST'])
def scan_usb_route():
    result = scan_usb_drives()
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
