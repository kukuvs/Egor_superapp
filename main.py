import os
import json
import mmap
import time
import platform
import psutil
import subprocess
import fcntl
import logging

logging.basicConfig(level=logging.DEBUG, format='[SERVER] %(asctime)s %(levelname)s: %(message)s')

SHARED_MEM_FILE = '/tmp/sysmon_shared_mem'
SHARED_MEM_SIZE = 200 * 1024  # 10 KB

def lock_file(f):
    fcntl.flock(f.fileno(), fcntl.LOCK_EX)

def unlock_file(f):
    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

def get_processes():
    return [proc.info for proc in psutil.process_iter(['pid', 'name', 'username'])]

def get_gpu_info():
    try:
        result = subprocess.run('lspci | grep VGA', shell=True, stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip().split('\n')
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
        return recent_files if recent_files else ["No files created in the last 60 seconds"]
    except Exception as e:
        return [f"Error detecting file creation: {e}"]

def get_uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        h = int(uptime_seconds // 3600)
        m = int((uptime_seconds % 3600) // 60)
        s = int(uptime_seconds % 60)
        return f"Uptime: {h}h {m}m {s}s"
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
        return result.stdout.decode('utf-8', errors='replace')
    except Exception as e:
        return f"Error getting network config: {e}"

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8', errors='replace')
    except subprocess.CalledProcessError as e:
        return e.stderr.decode('utf-8', errors='replace')

def handle_request(request_json):
    try:
        logging.debug(f"Handling request JSON: {request_json}")
        request = json.loads(request_json)
        cmd = request.get('command')
        logging.debug(f"Command received: {cmd}")
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
            response = execute_command(request.get('data', ''))
        else:
            response = {'error': 'Unknown command'}
    except Exception as e:
        logging.error(f"Exception in handle_request: {e}", exc_info=True)
        response = {'error': str(e)}
    response_json = json.dumps(response, ensure_ascii=False)
    logging.debug(f"Response JSON: {response_json}")
    return response_json

def server_loop():
    logging.info("Starting server loop")

    # Создаём или перезаписываем файл с нужным размером
    with open(SHARED_MEM_FILE, 'wb') as f:
        f.write(b'\x00' * SHARED_MEM_SIZE)
    logging.info(f"Shared memory file created/reset: {SHARED_MEM_FILE}")

    with open(SHARED_MEM_FILE, 'r+b') as f:
        mm = mmap.mmap(f.fileno(), SHARED_MEM_SIZE)

        logging.info("Server started, waiting for requests...")

        while True:
            time.sleep(0.1)  # Пауза для снижения нагрузки

            try:
                lock_file(f)
                mm.seek(0)
                raw = mm.read(SHARED_MEM_SIZE)
                raw = raw.split(b'\x00', 1)[0]
                if not raw:
                    unlock_file(f)
                    continue  # Нет запроса, ждем дальше

                request_json = raw.decode('utf-8')
                logging.debug(f"Received request JSON: {request_json}")

                response_json = handle_request(request_json)

                mm.seek(0)
                encoded = response_json.encode('utf-8')
                if len(encoded) > SHARED_MEM_SIZE:
                    logging.warning("Response truncated due to size limit")
                    encoded = encoded[:SHARED_MEM_SIZE]
                mm.write(encoded)
                mm.write(b'\x00' * (SHARED_MEM_SIZE - len(encoded)))

                # Очищаем запрос, чтобы клиент понял, что ответ готов
                mm.flush()
                mm.seek(0)
                mm.write(b'\x00' * SHARED_MEM_SIZE)
                mm.flush()

                unlock_file(f)
                logging.debug("Response written and lock released")

            except Exception as e:
                logging.error(f"Error processing request: {e}", exc_info=True)
                try:
                    unlock_file(f)
                except:
                    pass

if __name__ == "__main__":
    if platform.system().lower() != 'linux':
        print("This server works only on Linux.")
        exit(1)
    server_loop()
