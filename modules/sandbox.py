import requests
import subprocess
import time
import os

VM_IP = '192.168.6.128'
VM_PORT = 8888
SNAPSHOT_NAME = 'CleanState'
VMRUN_PATH = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
VMX_PATH = r"C:\Users\Dell\Documents\Virtual Machines\Windows10\Windows10.vmx"
# المسار اللي هيتحفظ فيه الـ CSV log على جهازك
LOG_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uploads')


def revert_to_snapshot():
    """بيرجّع الـ VM للـ Snapshot النظيف"""
    try:
        result = subprocess.run([
            VMRUN_PATH, 'revertToSnapshot',
            VMX_PATH, SNAPSHOT_NAME
        ], capture_output=True, text=True)

        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        print(f"Return code: {result.returncode}")

        if result.returncode == 0:
            print("✅ Reverted to CleanState")
            time.sleep(5)
            return True
        else:
            print(f"❌ Revert failed")
            return False
    except Exception as e:
        print(f"❌ Revert exception: {e}")
        return False


def start_vm():
    """بيشغّل الـ VM"""
    try:
        result = subprocess.run([
            VMRUN_PATH, 'start', VMX_PATH
        ], capture_output=True, text=True)

        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        print(f"Return code: {result.returncode}")

        if result.returncode == 0:
            print("✅ VM Started, waiting 20 seconds...")
            time.sleep(20)
            return True
        else:
            print(f"❌ VM start failed")
            return False
    except Exception as e:
        print(f"❌ Start exception: {e}")
        return False

def send_file_to_agent(filepath, filename):
    """بيبعت الملف للـ Agent جوّا الـ VM"""
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()

        print(f"📤 Sending {filename} to VM agent...")
        response = requests.post(
            f'http://{VM_IP}:{VM_PORT}/analyze',
            data=file_data,
            headers={
                'Content-Length': str(len(file_data)),
                'X-Filename': filename
            },
            timeout=120
        )

        if response.status_code == 200:
            return response.json()
        else:
            print(f"❌ Agent returned status: {response.status_code}")
            return None

    except Exception as e:
        print(f"❌ Failed to send file: {e}")
        return None

def save_events_as_csv(events, filename):
    """بيحفظ الـ events كـ CSV عشان الـ behavior engine يقدر يقراها"""
    import csv

    csv_path = os.path.join(LOG_OUTPUT_DIR, f'{filename}_sandbox_log.csv')

    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['timestamp', 'type', 'Message'])
        writer.writeheader()

        for event in events:
            writer.writerow({
                'timestamp': event.get('timestamp', ''),
                'type': event.get('type', ''),
                'Message': str(event.get('data', ''))
            })

    print(f"✅ CSV log saved: {csv_path}")
    return csv_path

def run_sandbox_analysis(filepath, filename):
    """الدالة الرئيسية للـ Sandbox"""
    print(f"\n🔄 Starting Sandbox Analysis for: {filename}")

    # 1. رجوع للـ Snapshot النظيف
    print("🔄 Reverting to clean snapshot...")
    if not revert_to_snapshot():
        return {'success': False, 'events': [], 'csv_log_path': None}

    # 2. تشغيل الـ VM
    print("🔄 Starting VM...")
    if not start_vm():
        return {'success': False, 'events': [], 'csv_log_path': None}

    # 3. بعت الملف للـ Agent
    print("🔄 Sending file to agent...")
    events = send_file_to_agent(filepath, filename)

    if not events:
        return {'success': False, 'events': [], 'csv_log_path': None}

    # 4. حفظ الـ events كـ CSV
    csv_path = save_events_as_csv(events, filename)

    print(f"✅ Sandbox Analysis Complete! Got {len(events)} events")

    return {
        'success': True,
        'events': events,
        'total_events': len(events),
        'csv_log_path': csv_path
    }