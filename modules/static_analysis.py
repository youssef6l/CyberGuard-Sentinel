import pefile
import string

# الـ strings المشبوهة اللي بندور عليها
SUSPICIOUS_STRINGS = [
    'cmd', 'powershell', 'http', 'https',
    'registry', 'regedit', 'wget', 'curl',
    'CreateRemoteThread', 'VirtualAlloc',
    'WriteProcessMemory', 'ShellExecute',
    'WScript', 'base64'
]

# الـ imports المشبوهة
SUSPICIOUS_IMPORTS = [
    'CreateRemoteThread', 'VirtualAllocEx',
    'WriteProcessMemory', 'SetWindowsHookEx',
    'GetAsyncKeyState', 'URLDownloadToFile'
]


def extract_strings(filepath):
    """بتستخرج كل الـ strings من الملف"""
    found_strings = []
    with open(filepath, 'rb') as f:
        data = f.read()

    current = ""
    for byte in data:
        char = chr(byte)
        if char in string.printable and char not in '\n\r\t':
            current += char
        else:
            if len(current) >= 4:
                found_strings.append(current)
            current = ""

    return found_strings


def check_suspicious_strings(strings_list):
    """بتشوف لو في strings مشبوهة"""
    found = []
    for s in strings_list:
        for suspicious in SUSPICIOUS_STRINGS:
            if suspicious.lower() in s.lower():
                found.append(s)
                break
    return found


def analyze_pe_headers(filepath):
    """بتحلل الـ PE headers بتاعة الـ .exe"""
    result = {
        'is_valid_pe': False,
        'imports': [],
        'suspicious_imports': [],
        'sections': [],
        'is_packed': False
    }

    try:
        pe = pefile.PE(filepath)
        result['is_valid_pe'] = True

        # استخراج الـ imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                result['imports'].append(dll_name)

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        if func_name in SUSPICIOUS_IMPORTS:
                            result['suspicious_imports'].append(func_name)

        # استخراج الـ sections
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip()
            result['sections'].append(section_name)

        # كشف لو الملف متعبّى (Packed)
        if len(pe.sections) < 3:
            result['is_packed'] = True

    except Exception as e:
        result['error'] = str(e)

    return result


def run_static_analysis(filepath):
    """الدالة الرئيسية اللي بتشغّل كل التحليل"""

    # استخراج الـ strings
    all_strings = extract_strings(filepath)
    suspicious_strings = check_suspicious_strings(all_strings)

    # تحليل الـ PE headers
    pe_analysis = analyze_pe_headers(filepath)

    return {
        'total_strings': len(all_strings),
        'suspicious_strings': suspicious_strings[:20],  # أول 20 بس
        'pe_analysis': pe_analysis
    }