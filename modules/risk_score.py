"""
risk_score.py
-------------
Combines results from all analysis modules into a single 0-100 risk score.
"""

# ── Weights (must sum to 100) ─────────────────────────────────────────────────
WEIGHTS = {
    'virustotal' : 35,
    'yara'       : 25,
    'static'     : 20,
    'behavior'   : 15,
    'sandbox'    : 5,
}

# ── Threat levels ─────────────────────────────────────────────────────────────
THREAT_LEVELS = [
    (85, 'CRITICAL',  '🔴'),
    (65, 'HIGH',      '🟠'),
    (40, 'MEDIUM',    '🟡'),
    (20, 'LOW',       '🔵'),
    (0,  'CLEAN',     '🟢'),
]

RECOMMENDATIONS = {
    'CRITICAL' : "Quarantine immediately. Do NOT execute. Contact your security team.",
    'HIGH'     : "High confidence threat. Isolate system and delete the file.",
    'MEDIUM'   : "Suspicious file. Investigate before allowing execution.",
    'LOW'      : "Minor indicators. Monitor and investigate if in doubt.",
    'CLEAN'    : "No significant threats detected. Exercise normal caution.",
}


# ── Sub-scorers ───────────────────────────────────────────────────────────────

def _score_virustotal(vt: dict):
    reasons = []
    if not vt or not vt.get('found'):
        reasons.append("File not found in VirusTotal (slightly suspicious)")
        return 15.0, reasons

    malicious      = vt.get('malicious', 0)
    suspicious     = vt.get('suspicious', 0)
    total_engines  = vt.get('total_engines', 1) or 1
    detection_ratio = (malicious + suspicious * 0.5) / total_engines
    sub = round(min(detection_ratio * 140, 100), 1)

    if malicious > 0:
        reasons.append(f"{malicious}/{total_engines} AV engines flagged as malicious")
    if suspicious > 0:
        reasons.append(f"{suspicious} AV engine(s) flagged as suspicious")
    return sub, reasons


def _score_yara(yara_result: dict):
    reasons = []
    if not yara_result or not yara_result.get('matched'):
        return 0.0, reasons

    sev_map  = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'unknown': 30}
    top_sev  = yara_result.get('highest_severity', 'unknown')
    matches  = yara_result.get('matches', [])
    sub      = sev_map.get(top_sev, 30)
    bonus    = min((len(matches) - 1) * 5, 20)
    sub      = round(min(sub + bonus, 100), 1)

    rules_hit = [m['rule'] for m in matches[:4]]
    reasons.append(f"YARA: {len(matches)} rule(s) matched — {', '.join(rules_hit)}")
    cats = yara_result.get('categories', [])
    if cats:
        reasons.append(f"Categories detected: {', '.join(cats)}")
    return sub, reasons


def _score_static(static: dict):
    reasons = []
    sub = 0.0
    if not static:
        return 0.0, reasons

    sus_imports = static.get('suspicious_imports', [])
    if sus_imports:
        sub += min(len(sus_imports) * 8, 50)
        reasons.append(f"{len(sus_imports)} suspicious imports found")

    if static.get('is_packed'):
        sub += 25
        reasons.append("Binary appears packed/obfuscated")

    high_ent = static.get('high_entropy_sections', [])
    if high_ent:
        sub += min(len(high_ent) * 10, 20)
        reasons.append(f"{len(high_ent)} high-entropy section(s) detected")

    sus_sec = static.get('suspicious_sections', [])
    if sus_sec:
        sub += min(len(sus_sec) * 5, 15)
        reasons.append(f"Suspicious PE sections: {sus_sec}")

    return round(min(sub, 100), 1), reasons


def _score_behavior(behavior: dict):
    reasons = []
    sub = 0.0
    if not behavior:
        return 0.0, reasons

    cat_scores = {
        'persistence'       : 30,
        'evasion'           : 25,
        'discovery'         : 15,
        'download_execute'  : 35,
        'credential_access' : 35,
    }
    detected = behavior.get('detected_categories', [])
    for cat in detected:
        key   = cat.lower().replace(' ', '_').replace('&', '').strip('_')
        score = cat_scores.get(key, 20)
        sub  += score
        reasons.append(f"Behavior detected: {cat}")

    verdict = behavior.get('verdict', '').lower()
    if verdict in ('malware', 'malicious'):
        sub += 20
    elif verdict == 'suspicious':
        sub += 10

    return round(min(sub, 100), 1), reasons


def _score_sandbox(sandbox: dict):
    reasons = []
    sub = 0.0
    if not sandbox or not sandbox.get('success'):
        return 0.0, reasons

    for key, label, limit, pts in [
        ('network_connections',  'network connection(s)',     6,  40),
        ('file_modifications',   'file modification(s)',      6,  30),
        ('registry_modifications','registry modification(s)', 6,  30),
        ('spawned_processes',    'process(es) spawned',       8,  20),
    ]:
        items = sandbox.get(key, [])
        if items:
            sub += min(len(items) * pts, limit)
            reasons.append(f"Sandbox: {len(items)} {label} observed")

    return round(min(sub, 100), 1), reasons


# ── Main public function ──────────────────────────────────────────────────────

def calculate_risk_score(
    vt_result       = None,
    yara_result     = None,
    static_result   = None,
    behavior_result = None,
    sandbox_result  = None,
) -> dict:
    """
    Returns:
        {
            'risk_score'    : int  (0-100),
            'threat_level'  : str  (CLEAN/LOW/MEDIUM/HIGH/CRITICAL),
            'threat_emoji'  : str,
            'factors'       : { module: {score, weight, weighted, reasons} },
            'all_reasons'   : [str],
            'recommendation': str,
        }
    """
    scores = {
        'virustotal' : _score_virustotal(vt_result      or {}),
        'yara'       : _score_yara      (yara_result    or {}),
        'static'     : _score_static    (static_result  or {}),
        'behavior'   : _score_behavior  (behavior_result or {}),
        'sandbox'    : _score_sandbox   (sandbox_result  or {}),
    }

    total_weighted = sum(
        (score / 100) * WEIGHTS[key]
        for key, (score, _) in scores.items()
    )
    final_score = round(min(total_weighted, 100))

    threat_level = 'CLEAN'
    threat_emoji = '🟢'
    for threshold, level, emoji in THREAT_LEVELS:
        if final_score >= threshold:
            threat_level = level
            threat_emoji = emoji
            break

    factors = {
        key: {
            'score'    : score,
            'weight'   : WEIGHTS[key],
            'weighted' : round((score / 100) * WEIGHTS[key], 2),
            'reasons'  : reasons,
        }
        for key, (score, reasons) in scores.items()
    }

    all_reasons = [r for _, (_, rs) in scores.items() for r in rs]

    return {
        'risk_score'    : final_score,
        'threat_level'  : threat_level,
        'threat_emoji'  : threat_emoji,
        'factors'       : factors,
        'all_reasons'   : all_reasons,
        'recommendation': RECOMMENDATIONS[threat_level],
    }
