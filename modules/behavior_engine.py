import csv
import os

DYNAMIC_INDICATORS = {
    'Download & Execute': ['curl', 'wget', 'bitsadmin', 'certutil', 'http'],
    'Persistence': ['reg add', 'schtasks', 'startup', 'currentversion\\run',
                    'software\\microsoft\\windows\\currentversion\\run'],
    'Evasion': ['powershell -enc', 'vssadmin', 'bcedit', 'clearev', 'hidden'],
    'Discovery': ['whoami', 'net user', 'ipconfig', 'systeminfo', 'netstat']
}

def analyze_dynamic_logs(csv_path):
    detected = []
    if not csv_path or not os.path.exists(csv_path):
        print(f"[-] Behavior Engine: CSV file not found at {csv_path}")
        return detected

    try:
        with open(csv_path, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                full_msg = row.get('Message', '').lower()
                for chain_name, indicators in DYNAMIC_INDICATORS.items():
                    for ind in indicators:
                        if ind in full_msg:
                            detected.append({
                                'type': 'Dynamic Action',
                                'chain_name': chain_name,
                                'matched_indicator': ind,
                                'context': full_msg[:200]
                            })
    except Exception as e:
        print(f"[-] Analysis Error: {e}")

    return detected

def run_behavior_analysis(static_results, vt_result, csv_log_path=None):
    # تحليل الـ Dynamic logs
    dynamic_hits = analyze_dynamic_logs(csv_log_path)

    # حساب الـ verdict
    vt_malicious = vt_result.get('malicious', 0)
    is_malicious = vt_malicious > 0 or len(dynamic_hits) > 0

    verdict = "MALWARE" if is_malicious else "CLEAN"

    if len(dynamic_hits) > 2:
        threat_level = "CRITICAL"
    elif is_malicious:
        threat_level = "HIGH"
    else:
        threat_level = "LOW"

    return {
        'verdict': verdict,
        'threat_level': threat_level,
        'dynamic_analysis': {
            'hits_count': len(dynamic_hits),
            'detections': dynamic_hits
        },
        'static_summary': "Analyzed suspicious strings & imports"
    }