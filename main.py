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

FLAG_POS = 0  # позиция флага в mmap
FLAG_SIZE = 1  # размер флага в байтах
DATA_POS = FLAG_POS + FLAG_SIZE  # позиция начала данных

# Флаги состояния
FLAG_EMPTY = b'\x00'  # Буфер пуст, клиент может писать запрос
FLAG_REQUEST = b'\x01'  # Запрос записан, сервер может читать
FLAG_RESPONSE = b'\x02'  # Ответ записан, клиент может читать

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

    # Проверка и создание файла разделяемой памяти
    tmp_dir = os.path.dirname(SHARED_MEM_FILE)
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir, exist_ok=True)

    if not os.path.exists(SHARED_MEM_FILE):
        with open(SHARED_MEM_FILE, 'wb') as f:
            f.write(b'\x00' * SHARED_MEM_SIZE)
    else:
        size = os.path.getsize(SHARED_MEM_FILE)
        if size < SHARED_MEM_SIZE:
            with open(SHARED_MEM_FILE, 'ab') as f:
                f.write(b'\x00' * (SHARED_MEM_SIZE - size))

    with open(SHARED_MEM_FILE, 'r+b') as f:
        mm = mmap.mmap(f.fileno(), SHARED_MEM_SIZE)

        logging.info("Server started, waiting for requests...")

        while True:
            time.sleep(0.05)  # Небольшая пауза для снижения нагрузки

            try:
                lock_file(f)
                mm.seek(FLAG_POS)
                flag = mm.read(FLAG_SIZE)

                if flag != FLAG_REQUEST:
                    # Нет запроса, отпускаем блокировку и ждем
                    unlock_file(f)
                    continue

                # Читаем запрос
                mm.seek(DATA_POS)
                raw = mm.read(SHARED_MEM_SIZE - FLAG_SIZE)
                raw = raw.split(b'\x00', 1)[0]
                request_json = raw.decode('utf-8')
                logging.debug(f"Received request JSON: {request_json}")

                # Обрабатываем запрос
                response_json = handle_request(request_json)

                # Записываем ответ
                mm.seek(DATA_POS)
                encoded = response_json.encode('utf-8')
                if len(encoded) > SHARED_MEM_SIZE - FLAG_SIZE:
                    encoded = encoded[:SHARED_MEM_SIZE - FLAG_SIZE]
                mm.write(encoded)
                mm.write(b'\x00' * (SHARED_MEM_SIZE - FLAG_SIZE - len(encoded)))

                # Устанавливаем флаг, что ответ готов
                mm.seek(FLAG_POS)
                mm.write(FLAG_RESPONSE)
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
