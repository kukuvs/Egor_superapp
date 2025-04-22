import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import mmap
import os
import platform
import time
import fcntl
import logging
import sys

logging.basicConfig(level=logging.DEBUG, format='[CLIENT] %(asctime)s %(levelname)s: %(message)s')

SHARED_MEM_FILE = '/tmp/sysmon_shared_mem'
SHARED_MEM_SIZE = 10 * 1024  # 10 KB

FLAG_POS = 0
FLAG_SIZE = 1
DATA_POS = FLAG_POS + FLAG_SIZE

FLAG_EMPTY = b'\x00'
FLAG_REQUEST = b'\x01'
FLAG_RESPONSE = b'\x02'

def lock_file(f):
    fcntl.flock(f.fileno(), fcntl.LOCK_EX)

def unlock_file(f):
    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("System Monitor")
        self.geometry("900x700")
        self.create_widgets()

        if platform.system().lower() != 'linux':
            logging.error("This client works only on Linux.")
            sys.exit(1)

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

        self.mm_file = open(SHARED_MEM_FILE, 'r+b')
        self.mm = mmap.mmap(self.mm_file.fileno(), SHARED_MEM_SIZE)

    def send_request(self, command, data=None):
        logging.debug(f"Sending request: command={command}, data={data}")
        request_data = {'command': command}
        if data:
            request_data['data'] = data
        request_json = json.dumps(request_data, ensure_ascii=False)

        try:
            lock_file(self.mm_file)
            # Ждем, пока флаг станет пустым (0)
            while True:
                self.mm.seek(FLAG_POS)
                flag = self.mm.read(FLAG_SIZE)
                if flag == FLAG_EMPTY:
                    break
                unlock_file(self.mm_file)
                time.sleep(0.05)
                lock_file(self.mm_file)

            # Записываем запрос
            self.mm.seek(DATA_POS)
            self.mm.write(request_json.encode('utf-8'))
            self.mm.write(b'\x00' * (SHARED_MEM_SIZE - FLAG_SIZE - len(request_json)))

            # Устанавливаем флаг запроса
            self.mm.seek(FLAG_POS)
            self.mm.write(FLAG_REQUEST)
            self.mm.flush()
            unlock_file(self.mm_file)
            logging.debug("Request written and flag set")

        except Exception as e:
            logging.error(f"Error writing request: {e}", exc_info=True)
            try:
                unlock_file(self.mm_file)
            except:
                pass
            return {'error': str(e)}

        # Ждем, пока сервер установит флаг ответа
        timeout = 10  # секунд
        interval = 0.05
        waited = 0
        while waited < timeout:
            try:
                lock_file(self.mm_file)
                self.mm.seek(FLAG_POS)
                flag = self.mm.read(FLAG_SIZE)
                if flag == FLAG_RESPONSE:
                    # Читаем ответ
                    self.mm.seek(DATA_POS)
                    raw = self.mm.read(SHARED_MEM_SIZE - FLAG_SIZE)
                    raw = raw.split(b'\x00', 1)[0]
                    response_json = raw.decode('utf-8')

                    # Сбрасываем флаг в пустой
                    self.mm.seek(FLAG_POS)
                    self.mm.write(FLAG_EMPTY)
                    self.mm.flush()
                    unlock_file(self.mm_file)

                    logging.debug(f"Received response JSON: {response_json}")
                    try:
                        response = json.loads(response_json)
                        return response
                    except Exception:
                        return {'error': 'Invalid JSON response'}

                unlock_file(self.mm_file)
            except Exception as e:
                logging.error(f"Error reading response: {e}", exc_info=True)
                try:
                    unlock_file(self.mm_file)
                except:
                    pass
                return {'error': str(e)}

            time.sleep(interval)
            waited += interval

        logging.error("Timeout waiting for response")
        return {'error': 'Timeout waiting for response'}

    def create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(expand=True, fill='both')

        self.process_frame = ttk.Frame(notebook)
        notebook.add(self.process_frame, text="Processes")
        self.create_process_tab()

        self.gpu_frame = ttk.Frame(notebook)
        notebook.add(self.gpu_frame, text="GPU Info")
        self.create_gpu_tab()

        self.file_creation_frame = ttk.Frame(notebook)
        notebook.add(self.file_creation_frame, text="File Creation")
        self.create_file_creation_tab()

        self.uptime_frame = ttk.Frame(notebook)
        notebook.add(self.uptime_frame, text="Uptime")
        self.create_uptime_tab()

        self.network_frame = ttk.Frame(notebook)
        notebook.add(self.network_frame, text="Network Config")
        self.create_network_tab()

        self.terminal_frame = ttk.Frame(notebook)
        notebook.add(self.terminal_frame, text="Terminal")
        self.create_terminal_tab()

    def create_process_tab(self):
        btn = ttk.Button(self.process_frame, text="Get Processes", command=self.get_processes)
        btn.pack(pady=5)

        columns = ("pid", "name", "username")
        self.process_table = ttk.Treeview(self.process_frame, columns=columns, show='headings')
        self.process_table.heading("pid", text="PID")
        self.process_table.heading("name", text="Name")
        self.process_table.heading("username", text="User")
        self.process_table.column("pid", width=80, anchor='center')
        self.process_table.column("name", width=300)
        self.process_table.column("username", width=200)
        self.process_table.pack(expand=True, fill='both', padx=10, pady=10)

        scrollbar = ttk.Scrollbar(self.process_frame, orient="vertical", command=self.process_table.yview)
        self.process_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

    def create_gpu_tab(self):
        btn = ttk.Button(self.gpu_frame, text="Get GPU Info", command=self.get_gpu_info)
        btn.pack(pady=5)

        self.gpu_text = scrolledtext.ScrolledText(self.gpu_frame, wrap=tk.WORD)
        self.gpu_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_file_creation_tab(self):
        btn = ttk.Button(self.file_creation_frame, text="Detect File Creation", command=self.detect_file_creation)
        btn.pack(pady=5)

        self.file_creation_text = scrolledtext.ScrolledText(self.file_creation_frame, wrap=tk.WORD)
        self.file_creation_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_uptime_tab(self):
        btn = ttk.Button(self.uptime_frame, text="Get Uptime", command=self.get_uptime)
        btn.pack(pady=5)

        self.uptime_label = ttk.Label(self.uptime_frame, text="", font=("Arial", 14))
        self.uptime_label.pack(pady=20)

    def create_network_tab(self):
        btn = ttk.Button(self.network_frame, text="Get Network Config", command=self.get_network_config)
        btn.pack(pady=5)

        self.network_text = scrolledtext.ScrolledText(self.network_frame, wrap=tk.WORD)
        self.network_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_terminal_tab(self):
        label = ttk.Label(self.terminal_frame, text="Enter Command:")
        label.pack(pady=5)

        self.command_entry = ttk.Entry(self.terminal_frame, width=80)
        self.command_entry.pack(pady=5)

        run_btn = ttk.Button(self.terminal_frame, text="Run Command", command=self.run_command)
        run_btn.pack(pady=5)

        self.output_text = scrolledtext.ScrolledText(self.terminal_frame, wrap=tk.WORD)
        self.output_text.pack(expand=True, fill='both', padx=10, pady=10)

    def get_processes(self):
        response = self.send_request('get_processes')
        if 'error' in response:
            self.show_error(self.process_table, response['error'])
            return
        for row in self.process_table.get_children():
            self.process_table.delete(row)
        for proc in response:
            self.process_table.insert('', 'end', values=(proc.get('pid', ''), proc.get('name', ''), proc.get('username', '')))

    def get_gpu_info(self):
        response = self.send_request('get_gpu_info')
        if 'error' in response:
            self.gpu_text.delete(1.0, tk.END)
            self.gpu_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.gpu_text.delete(1.0, tk.END)
        if isinstance(response, list):
            self.gpu_text.insert(tk.END, '\n'.join(response))
        else:
            self.gpu_text.insert(tk.END, str(response))

    def detect_file_creation(self):
        response = self.send_request('detect_file_creation')
        if 'error' in response:
            self.file_creation_text.delete(1.0, tk.END)
            self.file_creation_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.file_creation_text.delete(1.0, tk.END)
        if isinstance(response, list):
            self.file_creation_text.insert(tk.END, '\n'.join(response))
        else:
            self.file_creation_text.insert(tk.END, str(response))

    def get_uptime(self):
        response = self.send_request('get_uptime')
        if 'error' in response:
            self.uptime_label.config(text=f"Error: {response['error']}")
            return
        self.uptime_label.config(text=str(response))

    def get_network_config(self):
        response = self.send_request('get_network_config')
        if 'error' in response:
            self.network_text.delete(1.0, tk.END)
            self.network_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.network_text.delete(1.0, tk.END)
        self.network_text.insert(tk.END, response)

    def run_command(self):
        command = self.command_entry.get()
        response = self.send_request('execute_command', data=command)
        self.output_text.delete(1.0, tk.END)
        if isinstance(response, dict) and 'error' in response:
            self.output_text.insert(tk.END, f"Error: {response['error']}")
        else:
            self.output_text.insert(tk.END, response)

    def show_error(self, widget, message):
        if isinstance(widget, ttk.Treeview):
            for row in widget.get_children():
                widget.delete(row)
            widget.insert('', 'end', values=(message,))
        else:
            widget.delete(1.0, tk.END)
            widget.insert(tk.END, message)

if __name__ == "__main__":
    app = App()
    app.mainloop()
