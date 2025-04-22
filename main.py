import platform
import json
import psutil
import netifaces
import screeninfo
import subprocess
import mmap
import os
import time
import posix_ipc

SHARED_MEM_FILE = '/tmp/sysmon_shared_mem'
SHARED_MEM_SIZE = 100 * 1024  # 10 KB

SEM_REQUEST_NAME = "/sysmon_request_sem"
SEM_RESPONSE_NAME = "/sysmon_response_sem"

def get_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        processes.append(proc.info)
    return processes

def get_gpu_info():
    try:
        result = subprocess.run('lspci | grep VGA', shell=True, stdout=subprocess.PIPE)
        output = result.stdout.decode('utf-8').strip().split('\n')
        return output
    except Exception as e:
        return [f"Error getting GPU info: {e}"]

def detect_file_creation():
    home = os.path.expanduser("~")
    recent_files = []
    now = time.time()
    try:
        for root, dirs, files in os.walk(home):
            for name in files:
                path = os.path.join(root, name)
                try:
                    ctime = os.path.getctime(path)
                    if now - ctime <= 60:
                        recent_files.append(path)
                except Exception:
                    continue
        if recent_files:
            return recent_files
        else:
            return ["No files created in the last 60 seconds"]
    except Exception as e:
        return [f"Error detecting file creation: {e}"]

def get_uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        return f"Uptime: {hours}h {minutes}m {seconds}s"
    except Exception as e:
        return f"Error getting uptime: {e}"

def get_network_config():
    try:
        try:
            subprocess.run(['ifconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            cmd = 'ifconfig -a'
        except Exception:
            cmd = 'ip addr'
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8', errors='replace')
        return output
    except Exception as e:
        return f"Error getting network config: {e}"

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8', errors='replace')
        return output
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.decode('utf-8', errors='replace')
        return error_output

def handle_request(request_json):
    try:
        request = json.loads(request_json)
        cmd = request.get('command')
        if cmd == 'get_processes':
            response = get_processes()
        elif cmd == 'get_gpu_info':
            response = get_gpu_info()
        elif cmd == 'detect_file_creation':
            response = detect_file_creation()
        elif cmd == 'get_uptime':
            response = get_uptime()
        elif cmd == 'get_network_config':
            response = get_network_config()
        elif cmd == 'execute_command':
            command = request.get('data', '')
            response = execute_command(command)
        else:
            response = {'error': 'Unknown command'}
    except Exception as e:
        response = {'error': str(e)}
    return json.dumps(response, ensure_ascii=False)

def server_loop():
    # Создаем или перезаписываем файл с нужным размером
    with open(SHARED_MEM_FILE, 'wb') as f:
        f.write(b'\x00' * SHARED_MEM_SIZE)

    with open(SHARED_MEM_FILE, 'r+b') as f:
        mm = mmap.mmap(f.fileno(), SHARED_MEM_SIZE)
        sem_request = posix_ipc.Semaphore(SEM_REQUEST_NAME, flags=posix_ipc.O_CREAT, initial_value=0)
        sem_response = posix_ipc.Semaphore(SEM_RESPONSE_NAME, flags=posix_ipc.O_CREAT, initial_value=0)

        print("Server started, waiting for requests...")

        while True:
            sem_request.acquire()

            mm.seek(0)
            raw = mm.read(SHARED_MEM_SIZE)
            raw = raw.split(b'\x00', 1)[0]
            request_json = raw.decode('utf-8')

            response_json = handle_request(request_json)

            mm.seek(0)
            encoded = response_json.encode('utf-8')
            if len(encoded) > SHARED_MEM_SIZE:
                encoded = encoded[:SHARED_MEM_SIZE]
            mm.write(encoded)
            mm.write(b'\x00' * (SHARED_MEM_SIZE - len(encoded)))

            sem_response.release()

if __name__ == "__main__":
    if platform.system().lower() != 'linux':
        print("This server works only on Linux.")
        exit(1)
    server_loop()
