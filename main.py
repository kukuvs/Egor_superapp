import os
import json
import mmap
import time
import platform
import psutil
import subprocess
import fcntl
import logging
from datetime import datetime

logging.basicConfig(level=logging.DEBUG, format='[SERVER] %(asctime)s %(levelname)s: %(message)s', filename='server.log', filemode='a')

SHARED_MEM_FILE = '/tmp/sysmon_shared_mem'
SHARED_MEM_SIZE = 200 * 1024  # 200 KB

FLAG_POS = 0  # позиция флага в mmap
FLAG_SIZE = 1  # размер флага в байтах
DATA_POS = FLAG_POS + FLAG_SIZE  # позиция начала данных

# Флаги состояния
FLAG_EMPTY = b'\x00'  # Буфер пуст, клиент может писать запрос
FLAG_REQUEST = b'\x01'  # Запрос записан, сервер может читать
FLAG_RESPONSE = b'\x02'  # Ответ записан, клиент может читать

# Лог файл для процессов, запущенных во время работы сервера
PROCESS_LOG_FILE = '/tmp/superapp_processes.log'

# Список процессов при старте сервера (pid -> (name, create_time))
start_processes = {}

def lock_file(f):
    fcntl.flock(f.fileno(), fcntl.LOCK_EX)

def unlock_file(f):
    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

def get_processes():
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
        try:
            info = proc.info
            procs.append(info)
        except Exception:
            continue
    return procs

def log_new_processes():
    """Записываем в лог процессы, запущенные после старта сервера"""
    global start_processes
    current = {}
    new_procs = []
    for proc in psutil.process_iter(['pid', 'name', 'create_time']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            ctime = proc.info['create_time']
            current[pid] = (name, ctime)
            if pid not in start_processes or start_processes[pid][1] != ctime:
                new_procs.append((name, datetime.fromtimestamp(ctime).strftime('%Y-%m-%d %H:%M:%S')))
        except Exception:
            continue
    if new_procs:
        with open(PROCESS_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] New processes:\n")
            for name, start_time in new_procs:
                f.write(f"{name} - {start_time}\n")
    start_processes = current

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
        # Проверяем доступность ifconfig
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

def get_removable_devices():
    """Возвращает список съемных носителей"""
    devices = []
    try:
        partitions = psutil.disk_partitions(all=False)
        for p in partitions:
            # Фильтрация по mountpoint для съемных носителей
            if p.mountpoint.startswith('/media') or p.mountpoint.startswith('/run/media'):
                devices.append(f"{p.device} mounted on {p.mountpoint} ({p.fstype})")
        if not devices:
            return ["No removable devices found."]
        return devices
    except Exception as e:
        return [f"Error getting removable devices: {e}"]

def run_system_utility(name):
    """Запуск системных утилит по имени"""
    utilities = {
        'terminal': ['x-terminal-emulator'],  # или 'gnome-terminal', 'konsole' и т.п.
        'system_monitor': ['gnome-system-monitor'],
        'disk_usage': ['baobab'],  # Аналог "Управление дисками"
        'file_manager': ['nautilus'],
        'network_manager': ['nm-connection-editor'],
    }
    cmd = utilities.get(name)
    if not cmd:
        return f"Unknown utility: {name}"
    try:
        subprocess.Popen(cmd)
        return f"Utility {name} started."
    except Exception as e:
        return f"Error starting utility {name}: {e}"

# Реализация терминала с набором команд
def terminal_command_handler(command_line):
    """Обрабатывает команды терминала, поддерживает минимум 10 команд"""
    command_line = command_line.strip()
    if not command_line:
        return ""

    parts = command_line.split()
    cmd = parts[0]
    args = parts[1:]

    # Список поддерживаемых команд
    supported_cmds = {
        'ls': ['ls', '-la'] + args,
        'pwd': ['pwd'],
        'cd': None,  # cd нужно обрабатывать отдельно
        'cat': ['cat'] + args,
        'echo': ['echo'] + args,
        'ps': ['ps', 'aux'],
        'df': ['df', '-h'],
        'top': ['top', '-b', '-n', '1'],
        'kill': ['kill'] + args,
        'uptime': ['uptime'],
        'help': None,
    }

    if cmd not in supported_cmds:
        return f"Unknown command: {cmd}. Use 'help' to see available commands."

    if cmd == 'help':
        return ("Supported commands:\n"
                "ls, pwd, cd, cat, echo, ps, df, top, kill, uptime, help\n"
                "cd changes directory (only for current command execution, no persistent effect)")

    if cmd == 'cd':
        # cd не меняет директорию сервера, но можно проверить путь
        if len(args) != 1:
            return "Usage: cd <directory>"
        path = args[0]
        if os.path.isdir(path):
            return f"Changed directory to {path} (only for this command)"
        else:
            return f"No such directory: {path}"

    try:
        # Выполняем команду через subprocess
        proc = subprocess.run(supported_cmds[cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return proc.stdout
    except subprocess.CalledProcessError as e:
        return e.stderr

def handle_request(request_json):
    try:
        logging.debug(f"Handling request JSON: {request_json}")
        request = json.loads(request_json)
        cmd = request.get('command')
        data = request.get('data')
        logging.debug(f"Command received: {cmd} with data: {data}")

        # Логируем новые процессы при каждом запросе (можно оптимизировать)
        log_new_processes()

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
            response = execute_command(data if data else '')
        elif cmd == 'get_removable_devices':
            response = get_removable_devices()
        elif cmd == 'run_utility':
            # data - имя утилиты
            response = run_system_utility(data if data else '')
        elif cmd == 'terminal_command':
            response = terminal_command_handler(data if data else '')
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

    # Инициализация списка процессов при старте
    global start_processes
    start_processes = {}
    for proc in psutil.process_iter(['pid', 'name', 'create_time']):
        try:
            start_processes[proc.info['pid']] = (proc.info['name'], proc.info['create_time'])
        except Exception:
            continue

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
