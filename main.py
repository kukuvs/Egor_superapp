import platform
import json
import psutil
import netifaces
import screeninfo
import subprocess
import mmap
import os
import time
import fcntl  # для Linux
import msvcrt  # для Windows
import sys

SHARED_MEM_SIZE = 10 * 1024  # 10 KB

if platform.system() == 'Windows':
    SHARED_MEM_FILE = os.path.join(os.getenv('TEMP'), 'sysmon_shared_mem')
else:
    SHARED_MEM_FILE = '/tmp/sysmon_shared_mem'

def lock_file(f):
    if platform.system() == 'Windows':
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, SHARED_MEM_SIZE)
    else:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)

def unlock_file(f):
    if platform.system() == 'Windows':
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, SHARED_MEM_SIZE)
    else:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

def get_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        processes.append(proc.info)
    return processes

def get_wireless_status():
    return psutil.net_if_stats()

def get_network_settings():
    return netifaces.interfaces()

def get_screen_resolution():
    screen = screeninfo.get_monitors()[0]
    return screen.width, screen.height

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output = result.stdout.decode('cp866')
        except UnicodeDecodeError:
            output = result.stdout.decode('cp866', errors='replace')
        return output
    except subprocess.CalledProcessError as e:
        try:
            error_output = e.stderr.decode('cp866')
        except UnicodeDecodeError:
            error_output = e.stderr.decode('cp866', errors='replace')
        return error_output

def get_network_config():
    try:
        system = platform.system().lower()
        if system == 'windows':
            cmd = 'ipconfig /all'
            encoding = 'cp866'
        else:
            try:
                subprocess.run(['ifconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                cmd = 'ifconfig -a'
            except Exception:
                cmd = 'ip addr'
            encoding = 'utf-8'

        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output = result.stdout.decode(encoding)
        except UnicodeDecodeError:
            output = result.stdout.decode(encoding, errors='replace')
        return output
    except Exception as e:
        return f"Error getting network config: {e}"

def handle_request(request_json):
    try:
        request = json.loads(request_json)
        cmd = request.get('command')
        if cmd == 'get_processes':
            response = get_processes()
        elif cmd == 'get_wireless_status':
            response = {k: v._asdict() for k, v in get_wireless_status().items()}
        elif cmd == 'get_network_config':
            response = get_network_config()
        elif cmd == 'get_network_settings':
            response = get_network_settings()
        elif cmd == 'get_screen_resolution':
            response = get_screen_resolution()
        elif cmd == 'execute_command':
            command = request.get('data', '')
            response = execute_command(command)
        else:
            response = {'error': 'Unknown command'}
    except Exception as e:
        response = {'error': str(e)}
    return json.dumps(response, ensure_ascii=False)

def server_loop():
    # Создаем файл, если не существует
    if not os.path.exists(SHARED_MEM_FILE):
        with open(SHARED_MEM_FILE, 'wb') as f:
            f.write(b'\x00' * SHARED_MEM_SIZE)

    with open(SHARED_MEM_FILE, 'r+b') as f:
        mm = mmap.mmap(f.fileno(), SHARED_MEM_SIZE)
        print("Server started, waiting for requests...")
        while True:
            # Ждем, пока клиент запишет запрос (простой polling)
            time.sleep(0.1)
            try:
                lock_file(f)
                mm.seek(0)
                raw = mm.read(SHARED_MEM_SIZE)
                raw = raw.split(b'\x00', 1)[0]
                if not raw:
                    unlock_file(f)
                    continue
                request_json = raw.decode('utf-8')

                # Обрабатываем запрос
                response_json = handle_request(request_json)

                # Записываем ответ
                mm.seek(0)
                mm.write(response_json.encode('utf-8'))
                mm.write(b'\x00' * (SHARED_MEM_SIZE - len(response_json)))

                # Очищаем запрос (чтобы клиент знал, что ответ готов)
                mm.flush()
                mm.seek(0)
                mm.write(b'\x00' * SHARED_MEM_SIZE)
                mm.flush()
                unlock_file(f)
            except Exception as e:
                print(f"Error: {e}")
                unlock_file(f)

if __name__ == "__main__":
    server_loop()
