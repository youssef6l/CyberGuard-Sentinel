import os
import hashlib
import platform
import subprocess
import string
import json
import datetime
import re

# ========== Dangerous File Extensions ==========
DANGEROUS_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.vbe',
    '.js', '.jse', '.ws', '.wsh', '.msi', '.msp', '.ps1', '.psm1', '.psd1',
    '.reg', '.inf', '.lnk', '.hta', '.cpl', '.jar', '.rar', '.zip', '.iso',
    '.img', '.sys', '.drv', '.ocx', '.tmp'
}

# ========== Known Malware File Names ==========
KNOWN_MALWARE_NAMES = [
    'autorun.inf', 'autorun.exe', 'setup.exe', 'install.exe', 'update.exe',
    'patch.exe', 'crack.exe', 'keygen.exe', 'loader.exe', 'payload.exe',
    'agent.exe', 'svchost32.exe', 'explorer32.exe', 'winlogon32.exe',
    'lsass32.exe', 'csrss32.exe', 'services32.exe', 'taskhost32.exe',
    'rundll.exe', 'regsvr.exe', 'mshta.exe'
]

# ========== Suspicious File Name Patterns ==========
SUSPICIOUS_PATTERNS = [
    r'.*crack.*\.exe$', r'.*keygen.*\.exe$', r'.*hack.*\.exe$',
    r'.*cheat.*\.exe$', r'.*bypass.*\.exe$', r'.*patch.*\.exe$',
    r'.*serial.*\.exe$', r'.*activat.*\.exe$', r'.*loader.*\.exe$',
    r'.*inject.*\.exe$', r'.*trojan.*', r'.*virus.*', r'.*malware.*',
    r'.*spyware.*', r'.*ransomware.*', r'.*worm.*\.(exe|bat|vbs)$',
    r'invoice_\d+\.exe$', r'.*_setup\.exe$', r'.*free.*\.exe$'
]

# ========== Autorun Indicators ==========
AUTORUN_INDICATORS = ['autorun.inf', 'autorun.exe', 'autorum.ini']

# ========== Helper: File Hash ==========
def get_file_hash(filepath: str) -> str:
    try:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return 'N/A'

# ========== Helper: File Size ==========
def get_size_label(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f'{size_bytes} B'
    elif size_bytes < 1024 * 1024:
        return f'{size_bytes / 1024:.1f} KB'
    else:
        return f'{size_bytes / (1024 * 1024):.2f} MB'

# ========== Detect Removable Drives (Windows + Linux) ==========
def get_removable_drives() -> list:
    drives = []
    system = platform.system()

    if system == 'Windows':
        try:
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            drive_types = ctypes.windll.kernel32.GetDriveTypeW
            for letter in string.ascii_uppercase:
                if bitmask & (1 << (ord(letter) - ord('A'))):
                    drive_path = f'{letter}:\\'
                    drive_type = drive_types(drive_path)
                    # 2 = DRIVE_REMOVABLE
                    if drive_type == 2:
                        drives.append(drive_path)
        except Exception:
            # Fallback: try common letters
            for letter in ['D', 'E', 'F', 'G', 'H']:
                p = f'{letter}:\\'
                if os.path.exists(p):
                    drives.append(p)

    elif system == 'Linux':
        media_dirs = ['/media', '/mnt']
        for base in media_dirs:
            if os.path.exists(base):
                for entry in os.listdir(base):
                    full = os.path.join(base, entry)
                    if os.path.isdir(full):
                        drives.append(full)

    elif system == 'Darwin':
        volumes_dir = '/Volumes'
        if os.path.exists(volumes_dir):
            for entry in os.listdir(volumes_dir):
                full = os.path.join(volumes_dir, entry)
                if os.path.isdir(full) and entry not in ['Macintosh HD']:
                    drives.append(full)

    return drives

# ========== Scan a Single File ==========
def analyze_file(filepath: str, filename: str) -> dict:
    result = {
        'name': filename,
        'path': filepath,
        'size': 'N/A',
        'extension': os.path.splitext(filename)[1].lower(),
        'sha256': 'N/A',
        'is_dangerous_ext': False,
        'is_known_malware': False,
        'is_suspicious_pattern': False,
        'is_autorun': False,
        'risk_score': 0,
        'risk_level': 'Safe',
        'flags': []
    }

    # File size
    try:
        size_bytes = os.path.getsize(filepath)
        result['size'] = get_size_label(size_bytes)
    except Exception:
        pass

    # SHA256
    result['sha256'] = get_file_hash(filepath)

    # Extension check
    if result['extension'] in DANGEROUS_EXTENSIONS:
        result['is_dangerous_ext'] = True
        result['risk_score'] += 30
        result['flags'].append(f'Dangerous file extension: {result["extension"]}')

    # Known malware names
    if filename.lower() in KNOWN_MALWARE_NAMES:
        result['is_known_malware'] = True
        result['risk_score'] += 50
        result['flags'].append(f'Matches known malware filename: {filename}')

    # Autorun check
    if filename.lower() in AUTORUN_INDICATORS:
        result['is_autorun'] = True
        result['risk_score'] += 40
        result['flags'].append('Autorun file detected — common USB attack vector')

    # Suspicious name patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if re.match(pattern, filename.lower()):
            result['is_suspicious_pattern'] = True
            result['risk_score'] += 25
            result['flags'].append(f'Suspicious filename pattern detected: {filename}')
            break

    # Double extension (e.g., invoice.pdf.exe)
    parts = filename.split('.')
    if len(parts) > 2:
        hidden_ext = '.' + parts[-2].lower()
        if hidden_ext in {'.pdf', '.doc', '.jpg', '.png', '.txt', '.xls'}:
            result['risk_score'] += 35
            result['flags'].append(f'Double extension trick: appears as {hidden_ext} but is {result["extension"]}')

    # Hidden/system attributes on Windows
    if platform.system() == 'Windows':
        try:
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
            FILE_ATTRIBUTE_HIDDEN = 0x2
            FILE_ATTRIBUTE_SYSTEM = 0x4
            if attrs != -1:
                if attrs & FILE_ATTRIBUTE_HIDDEN:
                    result['risk_score'] += 20
                    result['flags'].append('File is hidden (hidden attribute set)')
                if attrs & FILE_ATTRIBUTE_SYSTEM:
                    result['risk_score'] += 15
                    result['flags'].append('File has system attribute set')
        except Exception:
            pass

    # Determine risk level
    score = result['risk_score']
    if score == 0:
        result['risk_level'] = 'Safe'
    elif score <= 25:
        result['risk_level'] = 'Low'
    elif score <= 50:
        result['risk_level'] = 'Medium'
    elif score <= 75:
        result['risk_level'] = 'High'
    else:
        result['risk_level'] = 'Critical'

    return result

# ========== Walk Drive Recursively ==========
def scan_drive(drive_path: str, max_files: int = 500) -> dict:
    scan_result = {
        'drive': drive_path,
        'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_files': 0,
        'total_size': 'N/A',
        'dangerous_files': [],
        'suspicious_files': [],
        'safe_files_count': 0,
        'autorun_found': False,
        'overall_risk': 'Safe',
        'overall_score': 0,
        'summary': '',
        'blocked': False,
        'error': None
    }

    all_files = []
    total_bytes = 0

    try:
        for root, dirs, files in os.walk(drive_path):
            # Skip hidden/system dirs
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in files:
                if len(all_files) >= max_files:
                    break
                fpath = os.path.join(root, fname)
                all_files.append((fpath, fname))
                try:
                    total_bytes += os.path.getsize(fpath)
                except Exception:
                    pass

    except PermissionError as e:
        scan_result['error'] = f'Permission denied accessing drive: {str(e)}'
        return scan_result

    scan_result['total_files'] = len(all_files)
    scan_result['total_size'] = get_size_label(total_bytes)

    dangerous = []
    suspicious = []
    safe_count = 0
    max_score = 0

    for fpath, fname in all_files:
        file_info = analyze_file(fpath, fname)

        if file_info['is_autorun']:
            scan_result['autorun_found'] = True

        score = file_info['risk_score']
        if score > max_score:
            max_score = score

        if file_info['risk_level'] in ('Critical', 'High'):
            dangerous.append(file_info)
        elif file_info['risk_level'] in ('Medium', 'Low'):
            suspicious.append(file_info)
        else:
            safe_count += 1

    scan_result['dangerous_files'] = dangerous
    scan_result['suspicious_files'] = suspicious
    scan_result['safe_files_count'] = safe_count
    scan_result['overall_score'] = max_score

    # Overall risk based on findings
    if dangerous:
        scan_result['overall_risk'] = 'Critical' if max_score > 75 else 'High'
        scan_result['blocked'] = True
        scan_result['summary'] = f'⛔ {len(dangerous)} dangerous file(s) detected. USB drive blocked.'
    elif suspicious:
        scan_result['overall_risk'] = 'Medium'
        scan_result['summary'] = f'⚠️ {len(suspicious)} suspicious file(s) found. Proceed with caution.'
    elif scan_result['autorun_found']:
        scan_result['overall_risk'] = 'High'
        scan_result['blocked'] = True
        scan_result['summary'] = '⛔ Autorun file detected. USB drive blocked.'
    else:
        scan_result['overall_risk'] = 'Safe'
        scan_result['summary'] = f'✅ No threats found. {safe_count} file(s) scanned — drive is clean.'

    return scan_result


# ========== Main Entry: Scan All USB Drives ==========
def scan_usb_drives() -> dict:
    drives = get_removable_drives()

    if not drives:
        return {
            'status': 'no_drives',
            'message': 'No removable USB drives detected.',
            'drives': []
        }

    results = []
    for drive in drives:
        drive_result = scan_drive(drive)
        results.append(drive_result)

    overall_blocked = any(r['blocked'] for r in results)
    return {
        'status': 'scanned',
        'drives_found': len(drives),
        'blocked': overall_blocked,
        'message': f'{len(drives)} USB drive(s) scanned.',
        'drives': results
    }
