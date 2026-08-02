"""
yara_scanner.py
---------------
Fix: Python reads both rule files AND the target file as bytes,
so YARA never touches any file path directly.
This solves the Arabic/Unicode path issue on Windows.
"""

import os
import yara

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR   = os.path.dirname(MODULE_DIR)
RULES_DIR  = os.path.join(BASE_DIR, 'yara_rules')

SEVERITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}


def _compile_rules():
    """Read .yar files as text strings, compile via sources= (no file paths given to YARA)."""
    if not os.path.isdir(RULES_DIR):
        print(f"[YARA] Rules directory not found: {RULES_DIR}")
        return None

    sources = {}
    for fname in os.listdir(RULES_DIR):
        if fname.endswith(('.yar', '.yara')):
            full_path = os.path.join(RULES_DIR, fname)
            namespace = fname.rsplit('.', 1)[0]
            try:
                with open(full_path, 'r', encoding='utf-8') as fh:
                    sources[namespace] = fh.read()
                print(f"[YARA] Loaded: {fname}")
            except Exception as e:
                print(f"[YARA] Could not read {fname}: {e}")

    if not sources:
        print(f"[YARA] No .yar files found in: {RULES_DIR}")
        return None

    try:
        return yara.compile(sources=sources)
    except yara.SyntaxError as e:
        print(f"[YARA] Compilation error: {e}")
        return None


def scan_file(filepath: str) -> dict:
    result = {
        'matched'          : False,
        'match_count'      : 0,
        'matches'          : [],
        'highest_severity' : 'none',
        'categories'       : [],
        'error'            : None
    }

    if not os.path.isfile(filepath):
        result['error'] = f"File not found: {filepath}"
        return result

    rules = _compile_rules()
    if rules is None:
        result['error'] = f"YARA rules not loaded. Check yara_rules/ at: {RULES_DIR}"
        return result

    # ── KEY FIX: read file bytes with Python, pass data= not filepath ──
    try:
        with open(filepath, 'rb') as fh:
            file_bytes = fh.read()
    except Exception as e:
        result['error'] = f"Could not read file: {e}"
        return result

    try:
        raw_matches = rules.match(data=file_bytes, timeout=60)  # data= not filepath
    except yara.TimeoutError:
        result['error'] = "YARA scan timed out (60s)"
        return result
    except yara.Error as e:
        result['error'] = f"YARA scan error: {e}"
        return result

    if not raw_matches:
        return result

    parsed   = []
    cats     = set()
    top_sev  = 0
    top_name = 'unknown'

    for match in raw_matches:
        meta        = match.meta or {}
        severity    = meta.get('severity', 'unknown').lower()
        category    = meta.get('category', 'unknown').lower()
        description = meta.get('description', '')
        strings_hit = list({s.identifier for s in match.strings})

        cats.add(category)
        sev_val = SEVERITY_ORDER.get(severity, 0)
        if sev_val > top_sev:
            top_sev  = sev_val
            top_name = severity

        parsed.append({
            'rule'        : match.rule,
            'namespace'   : match.namespace,
            'description' : description,
            'severity'    : severity,
            'category'    : category,
            'strings_hit' : strings_hit
        })

    parsed.sort(key=lambda m: SEVERITY_ORDER.get(m['severity'], 0), reverse=True)

    result['matched']          = True
    result['match_count']      = len(parsed)
    result['matches']          = parsed
    result['highest_severity'] = top_name
    result['categories']       = sorted(cats)
    return result
