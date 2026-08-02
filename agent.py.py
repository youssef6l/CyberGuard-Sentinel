import os
import json
import time
import socket
import threading
import subprocess
import psutil
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

# مجلد اللي هيتحفظ فيه الملفات
UPLOAD_DIR = r"C:\agent\samples"
LOG_DIR = r"C:\agent\logs"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

class MonitoringAgent:
    def __init__(self):
        self.events = []
        self.monitoring = False
        self.start_time = None

    def log_event(self, event_type, data):
        event = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': event_type,
            'data': data
        }
        self.events.append(event)

    def monitor_processes(self, duration=60):
        """بيراقب الـ processes اللي بتتعمل"""
        known_pids = set(p.pid for p in psutil.process_iter())
        end_time = time.time() + duration

        while self.monitoring and time.time() < end_time:
            current_pids = set(p.pid for p in psutil.process_iter())
            new_pids = current_pids - known_pids

            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    self.log_event('process_created', {
                        'pid': pid,
                        'name': proc.name(),
                        'cmdline': ' '.join(proc.cmdline()),
                        'exe': proc.exe()
                    })
                except:
                    pass

            known_pids = current_pids
            time.sleep(0.5)

    def monitor_files(self, duration=60):
        """بيراقب الـ files اللي بتتعمل أو بتتغير"""
        watched_dirs = [
            r"C:\Users\youssef\AppData\Roaming",
            r"C:\Windows\Temp",
            r"C:\Users\youssef\Desktop"
        ]

        initial_state = {}
        for d in watched_dirs:
            if os.path.exists(d):
                for f in os.listdir(d):
                    full_path = os.path.join(d, f)
                    try:
                        initial_state[full_path] = os.path.getmtime(full_path)
                    except:
                        pass

        end_time = time.time() + duration
        while self.monitoring and time.time() < end_time:
            for d in watched_dirs:
                if os.path.exists(d):
                    for f in os.listdir(d):
                        full_path = os.path.join(d, f)
                        try:
                            mtime = os.path.getmtime(full_path)
                            if full_path not in initial_state:
                                self.log_event('file_created', {'path': full_path})
                                initial_state[full_path] = mtime
                            elif initial_state[full_path] != mtime:
                                self.log_event('file_modified', {'path': full_path})
                                initial_state[full_path] = mtime
                        except:
                            pass
            time.sleep(1)

    def monitor_network(self, duration=60):
        """بيراقب الـ network connections"""
        known_connections = set()
        end_time = time.time() + duration

        while self.monitoring and time.time() < end_time:
            try:
                connections = psutil.net_connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        conn_id = f"{conn.raddr.ip}:{conn.raddr.port}"
                        if conn_id not in known_connections:
                            self.log_event('network_connection', {
                                'remote_ip': conn.raddr.ip,
                                'remote_port': conn.raddr.port,
                                'local_port': conn.laddr.port if conn.laddr else None
                            })
                            known_connections.add(conn_id)
            except:
                pass
            time.sleep(1)

    def run_sample(self, filepath, duration=60):
        """بيشغّل الملف ويراقبه"""
        self.events = []
        self.monitoring = True
        self.start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # بيشغّل الـ monitoring في threads منفصلة
        threads = [
            threading.Thread(target=self.monitor_processes, args=(duration,)),
            threading.Thread(target=self.monitor_files, args=(duration,)),
            threading.Thread(target=self.monitor_network, args=(duration,))
        ]

        for t in threads:
            t.daemon = True
            t.start()

        # بيشغّل الملف
        try:
            subprocess.Popen(filepath, shell=True)
            self.log_event('sample_executed', {'filepath': filepath})
        except Exception as e:
            self.log_event('execution_error', {'error': str(e)})

        # بيستنى مدة الـ monitoring
        time.sleep(duration)
        self.monitoring = False

        return self.events


agent = MonitoringAgent()


class AgentHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/analyze':
            # استقبال الملف
            content_length = int(self.headers['Content-Length'])
            file_data = self.rfile.read(content_length)
            filename = self.headers.get('X-Filename', 'sample.exe')

            # حفظ الملف
            filepath = os.path.join(UPLOAD_DIR, filename)
            with open(filepath, 'wb') as f:
                f.write(file_data)

            # تشغيل التحليل
            events = agent.run_sample(filepath, duration=30)

            # حفظ الـ logs
            log_path = os.path.join(LOG_DIR, filename + '_log.json')
            with open(log_path, 'w') as f:
                json.dump(events, f, indent=2)

            # إرجاع النتيجة
            response = json.dumps(events).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(response)

    def log_message(self, format, *args):
        pass


if __name__ == '__main__':
    # تثبيت psutil لو مش موجود
    os.system('pip install psutil')
    
    server = HTTPServer(('0.0.0.0', 8888), AgentHandler)
    print("Agent running on port 8888...")
    server.serve_forever()