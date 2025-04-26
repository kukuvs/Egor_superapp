import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import json
import mmap
import os
import platform
import time
import fcntl
import logging
import sys
import psutil

logging.basicConfig(level=logging.DEBUG, format='[CLIENT] %(asctime)s %(levelname)s: %(message)s')

SHARED_MEM_FILE = '/tmp/sysmon_shared_mem'
SHARED_MEM_SIZE = 200 * 1024  # 200 KB

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

        self.start_processes = self.get_current_processes_snapshot()

        self.create_menu()
        self.bind_hotkeys()
        self.init_drag_and_drop()

    def create_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="Горячие клавиши", command=self.show_hotkeys_help)
        help_menu.add_command(label="О программе", command=self.show_about)

    def show_hotkeys_help(self):
        help_text = (
            "Горячие клавиши:\n"
            "Ctrl+P - Получить процессы\n"
            "Ctrl+G - Получить информацию о GPU\n"
            "Ctrl+F - Обнаружить создание файлов\n"
            "Ctrl+U - Получить время работы системы\n"
            "Ctrl+N - Получить сетевую конфигурацию\n"
            "Ctrl+S - Сохранить отчет процессов\n"
            "Ctrl+T - Открыть терминал\n"
            "Ctrl+R - Обновить список съемных носителей\n"
            "Ctrl+L - Запустить системные утилиты\n"
        )
        messagebox.showinfo("Горячие клавиши", help_text)

    def show_about(self):
        messagebox.showinfo("О программе", "Суперапп версия 1.0\nРазработано на Python с использованием Tkinter.")

    def bind_hotkeys(self):
        self.bind('<Control-p>', lambda e: self.get_processes())
        self.bind('<Control-g>', lambda e: self.get_gpu_info())
        self.bind('<Control-f>', lambda e: self.detect_file_creation())
        self.bind('<Control-u>', lambda e: self.get_uptime())
        self.bind('<Control-n>', lambda e: self.get_network_config())
        self.bind('<Control-s>', lambda e: self.save_process_report())
        self.bind('<Control-t>', lambda e: self.open_terminal_tab())
        self.bind('<Control-r>', lambda e: self.get_removable_devices())
        self.bind('<Control-l>', lambda e: self.show_utilities_menu())

    def init_drag_and_drop(self):
        try:
            import tkinterdnd2
            self.dnd = tkinterdnd2.TkinterDnD.Tk()
            self.output_text.drop_target_register(tkinterdnd2.DND_FILES)
            self.output_text.dnd_bind('<<Drop>>', self.on_drop)
            logging.info("Drag and Drop поддерживается")
        except ImportError:
            logging.warning("tkinterdnd2 не установлен, Drag and Drop не поддерживается")

    def on_drop(self, event):
        files = self.tk.splitlist(event.data)
        self.output_text.insert(tk.END, f"Перетащенные файлы:\n")
        for f in files:
            self.output_text.insert(tk.END, f"{f}\n")

    def get_current_processes_snapshot(self):
        procs = {}
        for proc in psutil.process_iter(['pid', 'name', 'create_time']):
            try:
                procs[proc.info['pid']] = (proc.info['name'], proc.info['create_time'])
            except Exception:
                continue
        return procs

    def save_process_report(self):
        current_procs = self.get_current_processes_snapshot()
        new_procs = []
        for pid, (name, ctime) in current_procs.items():
            if pid not in self.start_processes or self.start_processes[pid][1] != ctime:
                new_procs.append((name, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ctime))))

        if not new_procs:
            messagebox.showinfo("Отчет", "Новые процессы не найдены.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Текстовые файлы", "*.txt")])
        if not file_path:
            return

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("Процессы, запущенные во время работы приложения:\n")
            for name, start_time in new_procs:
                f.write(f"{name} - {start_time}\n")

        messagebox.showinfo("Отчет", f"Отчет сохранен в {file_path}")

    def open_terminal_tab(self):
        self.notebook.select(self.terminal_frame)

    def show_utilities_menu(self):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Терминал", command=lambda: self.run_utility('terminal'))
        menu.add_command(label="Монитор ресурсов", command=lambda: self.run_utility('system_monitor'))
        menu.add_command(label="Управление дисками", command=lambda: self.run_utility('disk_usage'))
        menu.add_command(label="Файловый менеджер", command=lambda: self.run_utility('file_manager'))
        menu.add_command(label="Сетевые настройки", command=lambda: self.run_utility('network_manager'))
        try:
            x = self.winfo_pointerx()
            y = self.winfo_pointery()
            menu.tk_popup(x, y)
        finally:
            menu.grab_release()

    def run_utility(self, name):
        response = self.send_request('run_utility', data=name)
        messagebox.showinfo("Утилита", response)

    def create_widgets(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both')

        self.process_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.process_frame, text="Processes")
        self.create_process_tab()

        self.gpu_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.gpu_frame, text="GPU Info")
        self.create_gpu_tab()

        self.file_creation_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.file_creation_frame, text="File Creation")
        self.create_file_creation_tab()

        self.uptime_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.uptime_frame, text="Uptime")
        self.create_uptime_tab()

        self.network_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_frame, text="Network Config")
        self.create_network_tab()

        self.removable_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.removable_frame, text="Removable Devices")
        self.create_removable_tab()

        self.terminal_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.terminal_frame, text="Terminal")
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

    def create_removable_tab(self):
        btn = ttk.Button(self.removable_frame, text="Refresh Devices", command=self.get_removable_devices)
        btn.pack(pady=5)

        self.removable_text = scrolledtext.ScrolledText(self.removable_frame, wrap=tk.WORD)
        self.removable_text.pack(expand=True, fill='both', padx=10, pady=10)

    def get_removable_devices(self):
        response = self.send_request('get_removable_devices')
        if 'error' in response:
            self.removable_text.delete(1.0, tk.END)
            self.removable_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.removable_text.delete(1.0, tk.END)
        if isinstance(response, list):
            self.removable_text.insert(tk.END, '\n'.join(response))
        else:
            self.removable_text.insert(tk.END, str(response))

    def create_terminal_tab(self):
        label = ttk.Label(self.terminal_frame, text="Enter Command:")
        label.pack(pady=5)

        self.command_entry = ttk.Entry(self.terminal_frame, width=80)
        self.command_entry.pack(pady=5)
        self.command_entry.bind('<Return>', lambda e: self.run_command())

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
        if not command.strip():
            return
        response = self.send_request('terminal_command', data=command)
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

    def send_request(self, command, data=None):
        logging.debug(f"Sending request: command={command}, data={data}")
        request_data = {'command': command}
        if data:
            request_data['data'] = data
        request_json = json.dumps(request_data, ensure_ascii=False)

        try:
            lock_file(self.mm_file)
            while True:
                self.mm.seek(FLAG_POS)
                flag = self.mm.read(FLAG_SIZE)
                if flag == FLAG_EMPTY:
                    break
                unlock_file(self.mm_file)
                time.sleep(0.05)
                lock_file(self.mm_file)

            self.mm.seek(DATA_POS)
            self.mm.write(request_json.encode('utf-8'))
            self.mm.write(b'\x00' * (SHARED_MEM_SIZE - FLAG_SIZE - len(request_json)))

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

        timeout = 10
        interval = 0.05
        waited = 0
        while waited < timeout:
            try:
                lock_file(self.mm_file)
                self.mm.seek(FLAG_POS)
                flag = self.mm.read(FLAG_SIZE)
                if flag == FLAG_RESPONSE:
                    self.mm.seek(DATA_POS)
                    raw = self.mm.read(SHARED_MEM_SIZE - FLAG_SIZE)
                    raw = raw.split(b'\x00', 1)[0]
                    response_json = raw.decode('utf-8')

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

if __name__ == "__main__":
    app = App()
    app.mainloop()
