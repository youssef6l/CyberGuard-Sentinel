import requests
import time

API_KEY = '4d658af39fdd380b41e53f3f9930dfeb19d4c9751ce604b25aa86b2d23867b6b'

def check_hash_virustotal(file_hash):
    """
    بتبعت الـ hash لـ VirusTotal وبترجع النتيجة
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 404:
            return {
                'found': False,
                'message': 'File not found on VirusTotal'
            }

        if response.status_code == 401:
            return {
                'found': False,
                'message': 'Invalid API Key'
            }

        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']

        return {
            'found': True,
            'malicious': stats['malicious'],
            'suspicious': stats['suspicious'],
            'clean': stats['undetected'],
            'total_engines': sum(stats.values()),
            'verdict': 'Malware' if stats['malicious'] > 3 else
                       'Suspicious' if stats['malicious'] > 0 else 'Clean'
        }

    except Exception as e:
        return {
            'found': False,
            'message': str(e)
        }

def check_url_virustotal(url_to_check):
    """
    بتبعت الـ URL لـ VirusTotal وبترجع النتيجة
    """
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": API_KEY
    }

    try:
        # أول حاجة لازم نحول الـ URL لـ ID خاص بالـ VirusTotal
        response = requests.post(url, headers=headers, data={'url': url_to_check})
        if response.status_code != 200:
            return {
                'found': False,
                'message': f'Error submitting URL: {response.status_code}'
            }

        url_id = response.json()['data']['id']  # ده الـ ID الخاص بالـ URL

        # نجيب نتيجة التحليل
        analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        analysis_response = requests.get(analysis_url, headers=headers)
        if analysis_response.status_code != 200:
            return {
                'found': False,
                'message': f'Error fetching analysis: {analysis_response.status_code}'
            }

        stats = analysis_response.json()['data']['attributes']['last_analysis_stats']

        return {
            'found': True,
            'malicious': stats['malicious'],
            'suspicious': stats['suspicious'],
            'clean': stats['undetected'],
            'total_engines': sum(stats.values()),
            'verdict': 'Malicious' if stats['malicious'] > 3 else
                       'Suspicious' if stats['malicious'] > 0 else 'Clean'
        }

    except Exception as e:
        return {
            'found': False,
            'message': str(e)
        }